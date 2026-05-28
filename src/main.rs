use std::{
    collections::HashSet,
    env,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use dotenvy::dotenv;
use log::{error, info, warn};
use serenity::{
    async_trait,
    builder::{CreateEmbed, CreateMessage, GetMessages},
    model::{
        channel::{Attachment, ChannelType, GuildChannel, Message},
        colour::Colour,
        gateway::Ready,
        guild::{Member, PartialGuild},
        id::{ChannelId, GuildId, RoleId, UserId},
        permissions::Permissions,
    },
    prelude::*,
};
use tokio::{
    sync::{Mutex, RwLock, Semaphore},
    time::sleep,
};

const DELETE_BATCH_SIZE: usize = 100;

#[derive(Clone)]
struct Config {
    bot_token: String,
    monitored_channel_id: ChannelId,
    mod_log_channel_id: Option<ChannelId>,
    whitelist_file: PathBuf,
    channel_concurrency: usize,
    max_retries: usize,
    processing_debounce_seconds: u64,
}

struct SharedState {
    whitelist_role_ids: RwLock<HashSet<RoleId>>,
    processing_users: Mutex<HashSet<UserId>>,
    channel_semaphore: Arc<Semaphore>,
}

struct Handler {
    config: Arc<Config>,
    state: Arc<SharedState>,
}

#[async_trait]
impl EventHandler for Handler {
    async fn ready(&self, _ctx: Context, ready: Ready) {
        info!("Bot ready: {} (ID: {})", ready.user.name, ready.user.id);
    }

    async fn message(&self, ctx: Context, message: Message) {
        if message.author.bot {
            return;
        }

        if let Err(err) = self.process_commands(&ctx, &message).await {
            warn!("Command processing error: {err}");
        }

        let guild_id = match message.guild_id {
            Some(id) => id,
            None => return,
        };

        if message.channel_id != self.config.monitored_channel_id {
            return;
        }

        let author_id = message.author.id;

        if self
            .is_whitelisted(&ctx, guild_id, author_id)
            .await
            .unwrap_or(false)
        {
            info!(
                "User {} has whitelisted role; skipping moderation.",
                author_id
            );
            return;
        }

        {
            let mut processing = self.state.processing_users.lock().await;
            if processing.contains(&author_id) {
                info!("User {} already being processed; skipping.", author_id);
                return;
            }
            processing.insert(author_id);
        }

        let state = Arc::clone(&self.state);
        let debounce = self.config.processing_debounce_seconds;
        tokio::spawn(async move {
            sleep(Duration::from_secs(debounce)).await;
            let mut processing = state.processing_users.lock().await;
            processing.remove(&author_id);
        });

        info!(
            "Detected message by user {} in monitored channel; starting moderation flow.",
            author_id
        );

        self.ban_user(&ctx, guild_id, author_id).await;

        if let Some(mod_channel) = self.config.mod_log_channel_id {
            if let Err(err) = self
                .send_mod_log(&ctx, mod_channel, &message)
                .await
            {
                warn!("Failed to send mod log: {err}");
            }
        }

        let cutoff = Utc::now() - ChronoDuration::hours(1);
        if let Err(err) = self
            .scan_and_delete_for_user(&ctx, guild_id, author_id, cutoff)
            .await
        {
            error!("Error scanning/deleting messages for {}: {err}", author_id);
        }

        info!("Moderation flow finished for user {}", author_id);
    }
}

impl Handler {
    async fn process_commands(&self, ctx: &Context, message: &Message) -> anyhow::Result<()> {
        if !message.content.starts_with("!whitelist") {
            return Ok(());
        }

        let guild_id = match message.guild_id {
            Some(id) => id,
            None => return Ok(()),
        };

        if !self
            .has_moderator_permissions(ctx, guild_id, message.channel_id, message.author.id)
            .await?
        {
            message
                .channel_id
                .send_message(ctx, CreateMessage::new().content("You do not have permission to manage the whitelist."))
                .await?;
            return Ok(());
        }

        let mut parts = message.content.split_whitespace();
        parts.next();
        let subcommand = parts.next().unwrap_or("list");

        match subcommand {
            "add" => {
                let role_id = parts
                    .next()
                    .and_then(|value| value.parse::<u64>().ok())
                    .map(RoleId::new);
                if let Some(role_id) = role_id {
                    self.whitelist_add(ctx, message, role_id).await?;
                } else {
                    self.send_usage(ctx, message).await?;
                }
            }
            "remove" => {
                let role_id = parts
                    .next()
                    .and_then(|value| value.parse::<u64>().ok())
                    .map(RoleId::new);
                if let Some(role_id) = role_id {
                    self.whitelist_remove(ctx, message, role_id).await?;
                } else {
                    self.send_usage(ctx, message).await?;
                }
            }
            "list" => {
                self.whitelist_list(ctx, message).await?;
            }
            "reload" => {
                self.whitelist_reload(ctx, message).await?;
            }
            _ => {
                self.send_usage(ctx, message).await?;
            }
        }

        Ok(())
    }

    async fn send_usage(&self, ctx: &Context, message: &Message) -> anyhow::Result<()> {
        message
            .channel_id
            .send_message(
                ctx,
                CreateMessage::new().content(
                    "Usage: `!whitelist add <role_id>`, `!whitelist remove <role_id>`, `!whitelist list`, `!whitelist reload`",
                ),
            )
            .await?;
        Ok(())
    }

    async fn whitelist_add(
        &self,
        ctx: &Context,
        message: &Message,
        role_id: RoleId,
    ) -> anyhow::Result<()> {
        let mut whitelist = self.state.whitelist_role_ids.write().await;
        if whitelist.contains(&role_id) {
            message
                .channel_id
                .send_message(
                    ctx,
                    CreateMessage::new().content(format!("Role ID {role_id} is already whitelisted.")),
                )
                .await?;
            return Ok(());
        }

        whitelist.insert(role_id);
        save_whitelist(&self.config.whitelist_file, &whitelist)?;

        let role_name = message
            .guild_id
            .and_then(|guild_id| guild_id.to_guild_cached(ctx))
            .and_then(|guild| guild.roles.get(&role_id).map(|role| role.name.clone()));

        if let Some(role_name) = role_name {
            message
                .channel_id
                .send_message(
                    ctx,
                    CreateMessage::new()
                        .content(format!("Added role `{role_name}` ({role_id}) to whitelist.")),
                )
                .await?;
        } else {
            message
                .channel_id
                .send_message(
                    ctx,
                    CreateMessage::new().content(format!(
                        "Added role ID `{role_id}` to whitelist (role not found on this guild)."
                    )),
                )
                .await?;
        }

        Ok(())
    }

    async fn whitelist_remove(
        &self,
        ctx: &Context,
        message: &Message,
        role_id: RoleId,
    ) -> anyhow::Result<()> {
        let mut whitelist = self.state.whitelist_role_ids.write().await;
        if !whitelist.remove(&role_id) {
            message
                .channel_id
                .send_message(
                    ctx,
                    CreateMessage::new().content(format!("Role ID {role_id} is not in the whitelist.")),
                )
                .await?;
            return Ok(());
        }

        save_whitelist(&self.config.whitelist_file, &whitelist)?;
        message
            .channel_id
            .send_message(
                ctx,
                CreateMessage::new().content(format!("Removed role ID `{role_id}` from whitelist.")),
            )
            .await?;
        Ok(())
    }

    async fn whitelist_list(&self, ctx: &Context, message: &Message) -> anyhow::Result<()> {
        let whitelist = self.state.whitelist_role_ids.read().await;
        if whitelist.is_empty() {
            message
                .channel_id
                .send_message(ctx, CreateMessage::new().content("Whitelist is empty."))
                .await?;
            return Ok(());
        }

        let mut role_ids: Vec<_> = whitelist.iter().copied().collect();
        role_ids.sort_by_key(|role_id| role_id.get());

        let mut lines = Vec::new();
        if let Some(guild) = message
            .guild_id
            .and_then(|guild_id| guild_id.to_guild_cached(ctx))
        {
            for role_id in &role_ids {
                if let Some(role) = guild.roles.get(role_id) {
                    lines.push(format!("`{role_id}` — {}", role.name));
                } else {
                    lines.push(format!("`{role_id}` — (not present in this guild)"));
                }
            }
        } else {
            for role_id in &role_ids {
                lines.push(format!("`{role_id}`"));
            }
        }

        let body = lines.join("\n");
        message
            .channel_id
            .send_message(
                ctx,
                CreateMessage::new().content(format!("Whitelisted role IDs:\n{body}")),
            )
            .await?;
        Ok(())
    }

    async fn whitelist_reload(&self, ctx: &Context, message: &Message) -> anyhow::Result<()> {
        let new_whitelist = load_whitelist(&self.config.whitelist_file)?;
        let mut whitelist = self.state.whitelist_role_ids.write().await;
        *whitelist = new_whitelist;
        message
            .channel_id
            .send_message(
                ctx,
                CreateMessage::new().content(format!(
                    "Reloaded whitelist from disk: {} role IDs.",
                    whitelist.len()
                )),
            )
            .await?;
        Ok(())
    }

    async fn has_moderator_permissions(
        &self,
        ctx: &Context,
        guild_id: GuildId,
        channel_id: ChannelId,
        user_id: UserId,
    ) -> anyhow::Result<bool> {
        let member = match guild_id.member(ctx, user_id).await {
            Ok(member) => member,
            Err(_) => return Ok(false),
        };

        let (guild, channel) = if let Some(guild) = guild_id.to_guild_cached(ctx) {
            let channel = match guild.channels.get(&channel_id) {
                Some(channel) => channel.clone(),
                None => return Ok(false),
            };
            (PartialGuild::from(guild.clone()), channel)
        } else {
            let guild = guild_id.to_partial_guild(ctx).await?;
            let channel = match channel_id.to_channel(ctx).await? {
                serenity::model::channel::Channel::Guild(channel) => channel,
                _ => return Ok(false),
            };
            (guild, channel)
        };

        let permissions = guild.user_permissions_in(&channel, &member);
        Ok(permissions.contains(Permissions::MANAGE_GUILD)
            || permissions.contains(Permissions::ADMINISTRATOR))
    }

    async fn is_whitelisted(
        &self,
        ctx: &Context,
        guild_id: GuildId,
        user_id: UserId,
    ) -> anyhow::Result<bool> {
        let member = match guild_id.member(ctx, user_id).await {
            Ok(member) => member,
            Err(_) => return Ok(false),
        };
        let whitelist = self.state.whitelist_role_ids.read().await;
        Ok(member
            .roles
            .iter()
            .any(|role_id| whitelist.contains(role_id)))
    }

    async fn ban_user(&self, ctx: &Context, guild_id: GuildId, user_id: UserId) {
        let reason = format!("Posted in monitored channel {}", self.config.monitored_channel_id);
        if let Err(err) = backoff_retry(self.config.max_retries, || async {
            guild_id
                .ban_with_reason(ctx, user_id, 0, &reason)
                .await
        })
        .await
        {
            warn!("Failed to ban user {user_id}: {err}");
        } else {
            info!("Banned user {user_id}");
        }
    }

    async fn send_mod_log(
        &self,
        ctx: &Context,
        mod_channel_id: ChannelId,
        message: &Message,
    ) -> anyhow::Result<()> {
        let guild_id = match message.guild_id {
            Some(id) => id,
            None => return Ok(()),
        };
        let bot_id = ctx.cache.current_user().id;

        let (guild, mod_channel, channel_name) = if let Some(cached_guild) =
            guild_id.to_guild_cached(ctx)
        {
            let mod_channel = match cached_guild.channels.get(&mod_channel_id) {
                Some(channel) => channel.clone(),
                None => return Ok(()),
            };
            let channel_name = cached_guild
                .channels
                .get(&message.channel_id)
                .map(|channel| channel.name.clone())
                .unwrap_or_else(|| "unknown".to_string());
            (PartialGuild::from(cached_guild.clone()), mod_channel, channel_name)
        } else {
            let guild = guild_id.to_partial_guild(ctx).await?;
            let mod_channel = match mod_channel_id.to_channel(ctx).await? {
                serenity::model::channel::Channel::Guild(channel) => channel,
                _ => return Ok(()),
            };
            let channel_name = match message.channel_id.to_channel(ctx).await? {
                serenity::model::channel::Channel::Guild(channel) => channel.name.clone(),
                _ => "unknown".to_string(),
            };
            (guild, mod_channel, channel_name)
        };

        let bot_member = match guild_id.member(ctx, bot_id).await {
            Ok(member) => member,
            Err(_) => return Ok(()),
        };
        let permissions = guild.user_permissions_in(&mod_channel, &bot_member);
        if !permissions.send_messages() {
            return Ok(());
        }

        let mut embed = CreateEmbed::new()
            .title("Message deleted")
            .color(Colour::DARK_RED)
            .timestamp(message.timestamp);
        let channel_mention = format!("<#{}>", message.channel_id);
        let description = format!(
            ">>> **Channel:** {} ({})\n**Message ID:** {}\n**Message author:** <@{}> ({})\n**Message created:** <t:{}:R>",
            channel_name,
            channel_mention,
            message.id,
            message.author.id,
            message.author.name,
            message.timestamp.unix_timestamp(),
        );
        embed = embed.description(description);

        let content = if message.content.is_empty() {
            "(empty)".to_string()
        } else {
            message.content.clone()
        };
        embed = embed.field("Message", content, false);

        if let Some((image_url, attachment_lines)) = build_attachment_info(&message.attachments) {
            if let Some(image_url) = image_url {
                embed = embed.image(image_url);
            }
            if !attachment_lines.is_empty() {
                let mut attachment_text = attachment_lines.join("\n");
                if attachment_text.len() > 1020 {
                    attachment_text.truncate(1020);
                    attachment_text.push_str("...");
                }
                embed = embed.field(
                    format!("Attachments ({})", attachment_lines.len()),
                    attachment_text,
                    false,
                );
            }
        }

        let avatar_url = message.author.face();
        embed = embed.thumbnail(avatar_url);
        embed = embed.footer(serenity::builder::CreateEmbedFooter::new(format!(
            "User ID: {}",
            message.author.id
        )));

        let msg = CreateMessage::new().add_embed(embed);
        mod_channel_id.send_message(ctx, msg).await?;
        Ok(())
    }

    async fn scan_and_delete_for_user(
        &self,
        ctx: &Context,
        guild_id: GuildId,
        author_id: UserId,
        cutoff: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        info!("Starting cleanup for user {} in guild {}", author_id, guild_id);

        let bot_id = ctx.cache.current_user().id;
        let bot_member = match guild_id.member(ctx, bot_id).await {
            Ok(member) => member,
            Err(err) => {
                warn!("Failed to fetch bot member in guild {}: {err}", guild_id);
                return Ok(());
            }
        };

        let (guild, channels): (PartialGuild, Vec<GuildChannel>) = if let Some(cached_guild) =
            guild_id.to_guild_cached(ctx)
        {
            let channels = cached_guild
                .channels
                .values()
                .filter(|channel| channel.kind == ChannelType::Text)
                .cloned()
                .collect();
            (PartialGuild::from(cached_guild.clone()), channels)
        } else {
            let guild = guild_id.to_partial_guild(ctx).await?;
            let channels_map = guild_id.channels(ctx).await?;
            let channels = channels_map
                .values()
                .filter(|channel| channel.kind == ChannelType::Text)
                .cloned()
                .collect();
            (guild, channels)
        };

        let guild = Arc::new(guild);
        let bot_member = Arc::new(bot_member);

        let mut tasks = Vec::new();
        for channel in channels {
            let permit = self.state.channel_semaphore.clone().acquire_owned().await?;
            let ctx = ctx.clone();
            let config = Arc::clone(&self.config);
            let guild = Arc::clone(&guild);
            let bot_member = Arc::clone(&bot_member);
            let task = tokio::spawn(async move {
                let _permit = permit;
                scan_channel(
                    &ctx,
                    guild,
                    channel,
                    bot_member,
                    author_id,
                    cutoff,
                    config.max_retries,
                )
                .await;
            });
            tasks.push(task);
        }

        for task in tasks {
            let _ = task.await;
        }

        info!("Cleanup completed for user {}", author_id);
        Ok(())
    }
}

async fn scan_channel(
    ctx: &Context,
    guild: Arc<PartialGuild>,
    channel: GuildChannel,
    bot_member: Arc<Member>,
    author_id: UserId,
    cutoff: DateTime<Utc>,
    max_retries: usize,
) {
    let permissions = guild.user_permissions_in(&channel, &bot_member);

    if !(permissions.view_channel()
        && permissions.read_message_history()
        && permissions.manage_messages())
    {
        return;
    }

    let channel_id = channel.id;
    let mut to_delete: Vec<Message> = Vec::new();
    let mut before = None;

    loop {
        let mut builder = GetMessages::new().limit(100);
        if let Some(before) = before {
            builder = builder.before(before);
        }

        let messages = match channel_id.messages(ctx, builder).await {
            Ok(messages) => messages,
            Err(err) => {
                warn!("Error fetching messages for channel {}: {err}", channel_id);
                break;
            }
        };

        if messages.is_empty() {
            break;
        }

        let mut reached_cutoff = false;
        let cutoff_ts = cutoff.timestamp();
        for message in &messages {
            let created_at = message.timestamp.unix_timestamp();
            if created_at < cutoff_ts {
                reached_cutoff = true;
                continue;
            }
            if message.author.id == author_id {
                to_delete.push(message.clone());
            }
            if to_delete.len() >= DELETE_BATCH_SIZE {
                if let Err(err) = safe_bulk_delete(ctx, channel_id, &to_delete, max_retries).await {
                    warn!("Bulk delete failed: {err}");
                }
                to_delete.clear();
                sleep(Duration::from_millis(600)).await;
            }
        }

        if reached_cutoff {
            break;
        }

        before = messages.last().map(|msg| msg.id);
    }

    if !to_delete.is_empty() {
        if let Err(err) = safe_bulk_delete(ctx, channel_id, &to_delete, max_retries).await {
            warn!("Bulk delete failed: {err}");
        }
    }
}

async fn safe_bulk_delete(
    ctx: &Context,
    channel_id: ChannelId,
    messages: &[Message],
    max_retries: usize,
) -> anyhow::Result<()> {
    if messages.is_empty() {
        return Ok(());
    }

    let cutoff_ts = (Utc::now() - ChronoDuration::days(14)).timestamp();
    let fresh: Vec<Message> = messages
        .iter()
        .cloned()
        .filter(|msg| msg.timestamp.unix_timestamp() >= cutoff_ts)
        .collect();

    if fresh.is_empty() {
        return Ok(());
    }

    if fresh.len() == 1 {
        backoff_retry(max_retries, || async { fresh[0].delete(ctx).await }).await?;
    } else {
        let ids: Vec<_> = fresh.iter().map(|msg| msg.id).collect();
        backoff_retry(max_retries, || async { channel_id.delete_messages(ctx, ids.clone()).await })
            .await?;
    }

    Ok(())
}

fn build_attachment_info(attachments: &[Attachment]) -> Option<(Option<String>, Vec<String>)> {
    if attachments.is_empty() {
        return None;
    }

    let mut image_url = None;
    let mut lines = Vec::new();
    for attachment in attachments {
        if image_url.is_none() {
            if let Some(content_type) = &attachment.content_type {
                if content_type.starts_with("image/") {
                    image_url = Some(attachment.url.clone());
                }
            }
        }

        if let Some(content_type) = &attachment.content_type {
            lines.push(format!("[{}]({}) ({})", attachment.filename, attachment.url, content_type));
        } else {
            lines.push(format!("[{}]({})", attachment.filename, attachment.url));
        }
    }

    Some((image_url, lines))
}

async fn backoff_retry<F, Fut, T>(retries: usize, mut f: F) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, serenity::Error>>,
{
    let mut attempt = 0;
    let mut delay = Duration::from_secs(1);
    loop {
        attempt += 1;
        match f().await {
            Ok(result) => return Ok(result),
            Err(err) => {
                if attempt >= retries {
                    return Err(anyhow::anyhow!(err));
                }
                warn!("Transient error attempt {}/{}: {err}; retrying in {:?}", attempt, retries, delay);
                sleep(delay).await;
                delay *= 2;
            }
        }
    }
}

fn whitelist_path(raw_path: &str) -> PathBuf {
    let path = PathBuf::from(raw_path);
    if path.is_absolute() {
        path
    } else {
        env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join(path)
    }
}

fn load_whitelist(path: &PathBuf) -> anyhow::Result<HashSet<RoleId>> {
    if !path.exists() {
        info!("Whitelist file {} not present; starting with empty whitelist.", path.display());
        return Ok(HashSet::new());
    }

    let data = std::fs::read_to_string(path)?;
    let list: Vec<u64> = serde_json::from_str(&data).unwrap_or_default();
    Ok(list.into_iter().map(RoleId::new).collect())
}

fn save_whitelist(path: &PathBuf, role_ids: &HashSet<RoleId>) -> anyhow::Result<()> {
    let mut list: Vec<u64> = role_ids.iter().map(|id| id.get()).collect();
    list.sort_unstable();
    let json = serde_json::to_string_pretty(&list)?;
    let tmp_path = path.with_extension("tmp");
    std::fs::write(&tmp_path, json)?;
    std::fs::rename(tmp_path, path)?;
    Ok(())
}

fn build_config() -> anyhow::Result<Config> {
    dotenv().ok();

    let bot_token = env::var("BOT_TOKEN")?;
    if bot_token.trim().is_empty() {
        anyhow::bail!("BOT_TOKEN is empty. Set it in your environment or .env file.");
    }

    let monitored_channel_raw = env::var("MONITORED_CHANNEL_ID")?;
    if monitored_channel_raw.trim().is_empty() {
        anyhow::bail!(
            "MONITORED_CHANNEL_ID is empty. Set it in your environment or .env file."
        );
    }
    let monitored_channel_id: u64 = monitored_channel_raw.parse()?;

    let mod_log_channel_id = env::var("MOD_LOG_CHANNEL_ID")
        .ok()
        .and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                trimmed.parse::<u64>().ok()
            }
        })
        .map(ChannelId::new);

    let whitelist_file = whitelist_path(
        &env::var("WHITELIST_FILE").unwrap_or_else(|_| "whitelist_ids.json".to_string()),
    );

    let channel_concurrency = env::var("CHANNEL_CONCURRENCY")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(3);

    let max_retries = env::var("MAX_RETRIES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(5);

    let processing_debounce_seconds = env::var("PROCESSING_DEBOUNCE_SECONDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(30);

    Ok(Config {
        bot_token,
        monitored_channel_id: ChannelId::new(monitored_channel_id),
        mod_log_channel_id,
        whitelist_file,
        channel_concurrency,
        max_retries,
        processing_debounce_seconds,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let config = Arc::new(build_config()?);
    let whitelist = load_whitelist(&config.whitelist_file)?;

    let state = Arc::new(SharedState {
        whitelist_role_ids: RwLock::new(whitelist),
        processing_users: Mutex::new(HashSet::new()),
        channel_semaphore: Arc::new(Semaphore::new(config.channel_concurrency)),
    });

    let intents = GatewayIntents::GUILD_MESSAGES
        | GatewayIntents::MESSAGE_CONTENT
        | GatewayIntents::GUILD_MEMBERS
        | GatewayIntents::GUILDS;

    let handler = Handler {
        config: Arc::clone(&config),
        state: Arc::clone(&state),
    };

    let mut client = Client::builder(&config.bot_token, intents)
        .event_handler(handler)
        .await?;

    info!("Starting scammer_bye_bye bot");
    if let Err(err) = client.start().await {
        error!("Bot terminated with error: {err}");
    }

    Ok(())
}
