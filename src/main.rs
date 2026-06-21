use std::{
    collections::{BTreeMap, HashMap, HashSet},
    env,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use dotenvy::dotenv;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use serenity::{
    async_trait,
    builder::{
        CreateCommand, CreateCommandOption, CreateEmbed, CreateEmbedFooter,
        CreateInteractionResponse, CreateInteractionResponseMessage, CreateMessage, EditMessage,
        GetMessages,
    },
    model::{
        application::{
            Command, CommandDataOption, CommandDataOptionValue, CommandInteraction,
            CommandOptionType, Interaction,
        },
        channel::{Attachment, ChannelType, GuildChannel, Message},
        colour::Colour,
        gateway::Ready,
        guild::{
            Member, PartialGuild,
            audit_log::{Action, MemberAction},
        },
        id::{ChannelId, GuildId, MessageId, RoleId, UserId},
        permissions::Permissions,
    },
    prelude::*,
};
use tokio::{
    sync::{Mutex, RwLock, Semaphore},
    time::sleep,
};

const DELETE_BATCH_SIZE: usize = 100;
const RECENT_BAN_LIMIT: usize = 10;

#[derive(Clone)]
struct Config {
    bot_token: String,
    monitored_channel_id: ChannelId,
    mod_log_channel_id: Option<ChannelId>,
    whitelist_file: PathBuf,
    honeypot_state_file: PathBuf,
    channel_concurrency: usize,
    max_retries: usize,
    processing_debounce_seconds: u64,
}

struct SharedState {
    whitelist_role_ids: RwLock<HashMap<GuildId, HashSet<RoleId>>>,
    processing_users: Mutex<HashSet<UserId>>,
    honeypot: Mutex<HoneypotState>,
    channel_semaphore: Arc<Semaphore>,
}

struct Handler {
    config: Arc<Config>,
    state: Arc<SharedState>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
struct HoneypotState {
    warning_message_id: Option<u64>,
    recent_bans_message_id: Option<u64>,
    recent_bans: Vec<RecentBan>,
    total_bans: u64,
    last_audit_log_entry_id: Option<u64>,
}

#[derive(Clone, Deserialize, Serialize)]
struct RecentBan {
    user_id: u64,
    username: String,
    banned_at: i64,
    audit_log_entry_id: Option<u64>,
}

#[async_trait]
impl EventHandler for Handler {
    async fn ready(&self, ctx: Context, ready: Ready) {
        info!("Logged in as {} (ID: {}).", ready.user.name, ready.user.id);
        info!("Connected to {} guild(s).", ready.guilds.len());
        info!("Syncing slash commands...");
        if let Err(err) = self.register_commands(&ctx).await {
            warn!("Failed to register slash commands: {err}");
        } else {
            info!("Slash commands synced.");
        }
        if let Err(err) = self.initialize_honeypot_channel(&ctx).await {
            warn!("Failed to initialize honeypot embeds: {err}");
        }
    }

    async fn message(&self, ctx: Context, message: Message) {
        if message.author.bot {
            return;
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

        let banned = self.ban_user(&ctx, guild_id, author_id).await;
        if banned {
            if let Err(err) = self.record_honeypot_ban(&ctx, &message).await {
                warn!("Failed to record honeypot ban for {}: {err}", author_id);
            }
        }

        if let Some(mod_channel) = self.config.mod_log_channel_id {
            if let Err(err) = self.send_mod_log(&ctx, mod_channel, &message).await {
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

    async fn interaction_create(&self, ctx: Context, interaction: Interaction) {
        let Interaction::Command(command) = interaction else {
            return;
        };

        if command.data.name != "whitelist" {
            return;
        }

        if let Err(err) = self.handle_whitelist_command(&ctx, &command).await {
            warn!("Slash command handling error: {err}");
        }
    }
}

impl Handler {
    async fn initialize_honeypot_channel(&self, ctx: &Context) -> anyhow::Result<()> {
        let channel = match self.config.monitored_channel_id.to_channel(ctx).await? {
            serenity::model::channel::Channel::Guild(channel) => channel,
            _ => return Ok(()),
        };
        let guild_id = channel.guild_id;

        self.ensure_warning_embed(ctx).await?;
        if let Err(err) = self.backfill_recent_bans(ctx, guild_id).await {
            warn!("Failed to backfill recent bans from audit logs: {err}");
        }
        self.refresh_recent_bans_embed(ctx).await?;

        Ok(())
    }

    async fn ensure_warning_embed(&self, ctx: &Context) -> anyhow::Result<()> {
        let (existing_message_id, protected_message_id) = {
            let state = self.state.honeypot.lock().await;
            (state.warning_message_id, state.recent_bans_message_id)
        };

        let message_id = self
            .upsert_embed_message(
                ctx,
                existing_message_id,
                protected_message_id,
                build_warning_embed(),
            )
            .await?;

        let mut state = self.state.honeypot.lock().await;
        if state.warning_message_id != Some(message_id) {
            state.warning_message_id = Some(message_id);
            save_honeypot_state(&self.config.honeypot_state_file, &state)?;
        }

        Ok(())
    }

    async fn refresh_recent_bans_embed(&self, ctx: &Context) -> anyhow::Result<()> {
        let (existing_message_id, protected_message_id, recent_bans, total_bans) = {
            let state = self.state.honeypot.lock().await;
            (
                state.recent_bans_message_id,
                state.warning_message_id,
                state.recent_bans.clone(),
                state.total_bans,
            )
        };

        let message_id = self
            .upsert_embed_message(
                ctx,
                existing_message_id,
                protected_message_id,
                build_recent_bans_embed(&recent_bans, total_bans),
            )
            .await?;

        let mut state = self.state.honeypot.lock().await;
        if state.recent_bans_message_id != Some(message_id) {
            state.recent_bans_message_id = Some(message_id);
            save_honeypot_state(&self.config.honeypot_state_file, &state)?;
        }

        Ok(())
    }

    async fn backfill_recent_bans(&self, ctx: &Context, guild_id: GuildId) -> anyhow::Result<()> {
        let bot_id = ctx.cache.current_user().id;
        let last_seen_entry_id = {
            let state = self.state.honeypot.lock().await;
            state.last_audit_log_entry_id
        };

        let logs = guild_id
            .audit_logs(
                ctx,
                Some(Action::Member(MemberAction::BanAdd)),
                Some(bot_id),
                None,
                Some(100),
            )
            .await?;

        let channel_id_text = self.config.monitored_channel_id.get().to_string();
        let mut recent_matches = Vec::new();
        let mut latest_entry_id = last_seen_entry_id;
        let mut matching_entries_seen = 0_u64;

        for entry in logs.entries {
            let entry_id = entry.id.get();
            let Some(reason) = entry.reason.as_deref() else {
                continue;
            };
            if !reason.contains("Posted in monitored channel") || !reason.contains(&channel_id_text)
            {
                continue;
            }

            matching_entries_seen += 1;
            if last_seen_entry_id.is_some_and(|last_seen| entry_id <= last_seen) {
                continue;
            }

            let Some(target_id) = entry.target_id else {
                continue;
            };

            latest_entry_id = Some(latest_entry_id.map_or(entry_id, |latest| latest.max(entry_id)));
            let user_id = target_id.get();
            let username = logs
                .users
                .get(&UserId::new(user_id))
                .map(|user| user.name.clone())
                .unwrap_or_else(|| "unknown".to_string());

            recent_matches.push(RecentBan {
                user_id,
                username,
                banned_at: entry.id.created_at().unix_timestamp(),
                audit_log_entry_id: Some(entry_id),
            });
        }

        let mut state = self.state.honeypot.lock().await;
        if recent_matches.is_empty()
            && latest_entry_id == last_seen_entry_id
            && state.total_bans >= matching_entries_seen
        {
            return Ok(());
        }
        for ban in recent_matches.into_iter().rev() {
            add_recent_ban(&mut state, ban);
        }
        state.total_bans = state.total_bans.max(matching_entries_seen);
        state.last_audit_log_entry_id = latest_entry_id;
        save_honeypot_state(&self.config.honeypot_state_file, &state)?;

        Ok(())
    }

    async fn record_honeypot_ban(&self, ctx: &Context, message: &Message) -> anyhow::Result<()> {
        {
            let mut state = self.state.honeypot.lock().await;
            state.total_bans = state.total_bans.saturating_add(1);
            add_recent_ban(
                &mut state,
                RecentBan {
                    user_id: message.author.id.get(),
                    username: message.author.name.clone(),
                    banned_at: Utc::now().timestamp(),
                    audit_log_entry_id: None,
                },
            );
            save_honeypot_state(&self.config.honeypot_state_file, &state)?;
        }

        self.refresh_recent_bans_embed(ctx).await
    }

    async fn upsert_embed_message(
        &self,
        ctx: &Context,
        existing_message_id: Option<u64>,
        protected_message_id: Option<u64>,
        embed: CreateEmbed,
    ) -> anyhow::Result<u64> {
        if let Some(message_id) = existing_message_id.filter(|id| Some(*id) != protected_message_id)
        {
            match self
                .config
                .monitored_channel_id
                .edit_message(
                    ctx,
                    MessageId::new(message_id),
                    EditMessage::new().content("").embed(embed.clone()),
                )
                .await
            {
                Ok(message) => return Ok(message.id.get()),
                Err(err) => {
                    warn!(
                        "Failed to edit managed honeypot message {}; recreating it: {err}",
                        message_id
                    );
                }
            }
        }

        let message = self
            .config
            .monitored_channel_id
            .send_message(ctx, CreateMessage::new().embed(embed))
            .await?;
        Ok(message.id.get())
    }

    async fn register_commands(&self, ctx: &Context) -> anyhow::Result<()> {
        let role_id_option =
            CreateCommandOption::new(CommandOptionType::Role, "role", "Role to add or remove")
                .required(true);

        let command = CreateCommand::new("whitelist")
            .description("Manage the role whitelist")
            .default_member_permissions(Permissions::MANAGE_GUILD)
            .add_option(
                CreateCommandOption::new(
                    CommandOptionType::SubCommand,
                    "add",
                    "Add a role ID to the whitelist",
                )
                .add_sub_option(role_id_option.clone()),
            )
            .add_option(
                CreateCommandOption::new(
                    CommandOptionType::SubCommand,
                    "remove",
                    "Remove a role ID from the whitelist",
                )
                .add_sub_option(role_id_option),
            )
            .add_option(CreateCommandOption::new(
                CommandOptionType::SubCommand,
                "list",
                "List whitelisted role IDs",
            ))
            .add_option(CreateCommandOption::new(
                CommandOptionType::SubCommand,
                "reload",
                "Reload whitelist from disk",
            ));

        Command::set_global_commands(&ctx.http, vec![command]).await?;
        Ok(())
    }

    async fn handle_whitelist_command(
        &self,
        ctx: &Context,
        command: &CommandInteraction,
    ) -> anyhow::Result<()> {
        let guild_id = match command.guild_id {
            Some(id) => id,
            None => {
                self.respond_ephemeral(
                    ctx,
                    command,
                    "This command can only be used inside a server.",
                )
                .await?;
                return Ok(());
            }
        };

        if !self
            .has_moderator_permissions(ctx, guild_id, command.channel_id, command.user.id)
            .await?
        {
            self.respond_ephemeral(
                ctx,
                command,
                "You do not have permission to manage the whitelist.",
            )
            .await?;
            return Ok(());
        }

        let subcommand = match command.data.options.first() {
            Some(option) => option,
            None => {
                self.respond_ephemeral(ctx, command, "Missing subcommand.")
                    .await?;
                return Ok(());
            }
        };

        let result = match subcommand.name.as_str() {
            "add" => {
                let role_id = match Self::role_id_from_subcommand(subcommand) {
                    Some(role_id) => role_id,
                    None => {
                        self.respond_ephemeral(ctx, command, "Role is required.")
                            .await?;
                        return Ok(());
                    }
                };
                self.whitelist_add_role(ctx, guild_id, role_id).await
            }
            "remove" => {
                let role_id = match Self::role_id_from_subcommand(subcommand) {
                    Some(role_id) => role_id,
                    None => {
                        self.respond_ephemeral(ctx, command, "Role is required.")
                            .await?;
                        return Ok(());
                    }
                };
                self.whitelist_remove_role(guild_id, role_id).await
            }
            "list" => self.whitelist_list_text(ctx, guild_id).await,
            "reload" => self.whitelist_reload_text(guild_id).await,
            _ => Ok("Unknown subcommand.".to_string()),
        };

        let response = match result {
            Ok(text) => text,
            Err(err) => {
                warn!("Whitelist command failed: {err}");
                "An error occurred while processing the command.".to_string()
            }
        };

        self.respond_ephemeral(ctx, command, response).await?;
        Ok(())
    }

    async fn respond_ephemeral(
        &self,
        ctx: &Context,
        command: &CommandInteraction,
        content: impl Into<String>,
    ) -> anyhow::Result<()> {
        command
            .create_response(
                ctx,
                CreateInteractionResponse::Message(
                    CreateInteractionResponseMessage::new()
                        .content(content)
                        .ephemeral(true),
                ),
            )
            .await?;
        Ok(())
    }

    async fn whitelist_add_role(
        &self,
        ctx: &Context,
        guild_id: GuildId,
        role_id: RoleId,
    ) -> anyhow::Result<String> {
        let mut whitelist = self.state.whitelist_role_ids.write().await;
        let guild_roles = whitelist.entry(guild_id).or_default();
        if guild_roles.contains(&role_id) {
            return Ok(format!("Role ID {role_id} is already whitelisted."));
        }

        guild_roles.insert(role_id);
        save_whitelist(&self.config.whitelist_file, &whitelist)?;

        let role_name = self
            .role_name_map(ctx, guild_id)
            .await
            .and_then(|roles| roles.get(&role_id).cloned());

        let response = if let Some(role_name) = role_name {
            format!("Added role `{role_name}` ({role_id}) to whitelist.")
        } else {
            format!("Added role ID `{role_id}` to whitelist (role not found on this guild).")
        };

        Ok(response)
    }

    async fn whitelist_remove_role(
        &self,
        guild_id: GuildId,
        role_id: RoleId,
    ) -> anyhow::Result<String> {
        let mut whitelist = self.state.whitelist_role_ids.write().await;
        let guild_roles = match whitelist.get_mut(&guild_id) {
            Some(roles) => roles,
            None => {
                return Ok(format!("Role ID `{role_id}` is not in the whitelist."));
            }
        };

        if !guild_roles.remove(&role_id) {
            return Ok(format!("Role ID `{role_id}` is not in the whitelist."));
        }

        if guild_roles.is_empty() {
            whitelist.remove(&guild_id);
        }

        save_whitelist(&self.config.whitelist_file, &whitelist)?;
        Ok(format!("Removed role ID `{role_id}` from whitelist."))
    }

    async fn whitelist_list_text(
        &self,
        ctx: &Context,
        guild_id: GuildId,
    ) -> anyhow::Result<String> {
        let whitelist = self.state.whitelist_role_ids.read().await;
        let role_ids_set = match whitelist.get(&guild_id) {
            Some(roles) if !roles.is_empty() => roles,
            _ => return Ok("Whitelist is empty.".to_string()),
        };

        let mut role_ids: Vec<_> = role_ids_set.iter().copied().collect();
        role_ids.sort_by_key(|role_id| role_id.get());

        let role_names = self.role_name_map(ctx, guild_id).await;
        let mut lines = Vec::new();

        if let Some(role_names) = role_names {
            for role_id in &role_ids {
                if let Some(role_name) = role_names.get(role_id) {
                    lines.push(format!("`{role_id}` — {role_name}"));
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
        Ok(format!("Whitelisted role IDs:\n{body}"))
    }

    async fn whitelist_reload_text(&self, guild_id: GuildId) -> anyhow::Result<String> {
        let new_whitelist = load_whitelist(&self.config.whitelist_file)?;
        let mut whitelist = self.state.whitelist_role_ids.write().await;
        *whitelist = new_whitelist;
        let count = whitelist
            .get(&guild_id)
            .map(|roles| roles.len())
            .unwrap_or(0);
        Ok(format!(
            "Reloaded whitelist from disk: {} role IDs for this guild.",
            count
        ))
    }

    async fn role_name_map(
        &self,
        ctx: &Context,
        guild_id: GuildId,
    ) -> Option<HashMap<RoleId, String>> {
        if let Some(guild) = guild_id.to_guild_cached(ctx) {
            return Some(
                guild
                    .roles
                    .iter()
                    .map(|(id, role)| (*id, role.name.clone()))
                    .collect(),
            );
        }

        match guild_id.to_partial_guild(ctx).await {
            Ok(guild) => Some(
                guild
                    .roles
                    .into_iter()
                    .map(|(id, role)| (id, role.name))
                    .collect(),
            ),
            Err(_) => None,
        }
    }

    fn role_id_from_subcommand(option: &CommandDataOption) -> Option<RoleId> {
        let options = match &option.value {
            CommandDataOptionValue::SubCommand(options) => options,
            _ => return None,
        };

        options
            .iter()
            .find_map(|opt| match (&*opt.name, &opt.value) {
                ("role", CommandDataOptionValue::Role(role_id)) => Some(*role_id),
                _ => None,
            })
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
        let guild_roles = match whitelist.get(&guild_id) {
            Some(roles) => roles,
            None => return Ok(false),
        };
        Ok(member
            .roles
            .iter()
            .any(|role_id| guild_roles.contains(role_id)))
    }

    async fn ban_user(&self, ctx: &Context, guild_id: GuildId, user_id: UserId) -> bool {
        let reason = format!(
            "Posted in monitored channel {}",
            self.config.monitored_channel_id
        );
        if let Err(err) = backoff_retry(self.config.max_retries, || async {
            guild_id.ban_with_reason(ctx, user_id, 0, &reason).await
        })
        .await
        {
            warn!("Failed to ban user {user_id}: {err}");
            false
        } else {
            info!("Banned user {user_id}");
            true
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

        let (guild, mod_channel, channel_name) =
            if let Some(cached_guild) = guild_id.to_guild_cached(ctx) {
                let mod_channel = match cached_guild.channels.get(&mod_channel_id) {
                    Some(channel) => channel.clone(),
                    None => return Ok(()),
                };
                let channel_name = cached_guild
                    .channels
                    .get(&message.channel_id)
                    .map(|channel| channel.name.clone())
                    .unwrap_or_else(|| "unknown".to_string());
                (
                    PartialGuild::from(cached_guild.clone()),
                    mod_channel,
                    channel_name,
                )
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
        info!(
            "Starting cleanup for user {} in guild {}",
            author_id, guild_id
        );

        let bot_id = ctx.cache.current_user().id;
        let bot_member = match guild_id.member(ctx, bot_id).await {
            Ok(member) => member,
            Err(err) => {
                warn!("Failed to fetch bot member in guild {}: {err}", guild_id);
                return Ok(());
            }
        };

        let (guild, channels): (PartialGuild, Vec<GuildChannel>) =
            if let Some(cached_guild) = guild_id.to_guild_cached(ctx) {
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
        backoff_retry(max_retries, || async {
            channel_id.delete_messages(ctx, ids.clone()).await
        })
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
            lines.push(format!(
                "[{}]({}) ({})",
                attachment.filename, attachment.url, content_type
            ));
        } else {
            lines.push(format!("[{}]({})", attachment.filename, attachment.url));
        }
    }

    Some((image_url, lines))
}

fn build_warning_embed() -> CreateEmbed {
    CreateEmbed::new()
        .title("🚨 DO NOT POST HERE 🚨")
        .description(
            "If you post something here, you WILL BE BANNED INSTANTLY.\n\n\
This channel is a honeypot for compromised accounts and spam bots.\n\
⚠️ This is your only warning. Turn back now.\n\
This message is permanent. The channel is actively monitored.",
        )
        .color(Colour::DARK_RED)
}

fn build_recent_bans_embed(recent_bans: &[RecentBan], total_bans: u64) -> CreateEmbed {
    let displayed_total = total_bans.max(recent_bans.len() as u64);

    CreateEmbed::new()
        .title("📋 Recent Bans")
        .description(build_recent_bans_text(recent_bans))
        .color(Colour::DARK_RED)
        .footer(CreateEmbedFooter::new(format!(
            "Last 10 bans · {displayed_total} total · Updates automatically"
        )))
        .timestamp(serenity::model::Timestamp::now())
}

fn build_recent_bans_text(recent_bans: &[RecentBan]) -> String {
    if recent_bans.is_empty() {
        return "No honeypot bans recorded yet.".to_string();
    }

    recent_bans
        .iter()
        .take(RECENT_BAN_LIMIT)
        .map(|ban| {
            format!(
                "<@{}> ({}) — <t:{}:R>",
                ban.user_id, ban.username, ban.banned_at
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn add_recent_ban(state: &mut HoneypotState, ban: RecentBan) {
    state
        .recent_bans
        .retain(|existing| existing.user_id != ban.user_id);
    state.recent_bans.push(ban);
    state
        .recent_bans
        .sort_by(|left, right| right.banned_at.cmp(&left.banned_at));
    state.recent_bans.truncate(RECENT_BAN_LIMIT);
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
                warn!(
                    "Transient error attempt {}/{}: {err}; retrying in {:?}",
                    attempt, retries, delay
                );
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
        env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    }
}

fn load_whitelist(path: &PathBuf) -> anyhow::Result<HashMap<GuildId, HashSet<RoleId>>> {
    if !path.exists() {
        info!(
            "Whitelist file {} not present; starting with empty whitelist.",
            path.display()
        );
        return Ok(HashMap::new());
    }

    let data = std::fs::read_to_string(path)?;
    let value: serde_json::Value = serde_json::from_str(&data).unwrap_or_default();
    let mut result: HashMap<GuildId, HashSet<RoleId>> = HashMap::new();

    match value {
        serde_json::Value::Object(map) => {
            for (guild_id, roles_value) in map {
                let guild_id = match guild_id.parse::<u64>() {
                    Ok(id) => GuildId::new(id),
                    Err(_) => continue,
                };

                let roles = match roles_value {
                    serde_json::Value::Array(values) => values,
                    _ => continue,
                };

                let role_ids: HashSet<RoleId> = roles
                    .into_iter()
                    .filter_map(|value| value.as_u64())
                    .map(RoleId::new)
                    .collect();

                if !role_ids.is_empty() {
                    result.insert(guild_id, role_ids);
                }
            }
        }
        serde_json::Value::Array(_) => {
            warn!(
                "Whitelist file {} uses a legacy format. Please rebuild whitelist per guild.",
                path.display()
            );
        }
        _ => {}
    }

    Ok(result)
}

fn save_whitelist(
    path: &PathBuf,
    role_ids: &HashMap<GuildId, HashSet<RoleId>>,
) -> anyhow::Result<()> {
    let mut payload: BTreeMap<String, Vec<u64>> = BTreeMap::new();

    for (guild_id, roles) in role_ids {
        let mut list: Vec<u64> = roles.iter().map(|id| id.get()).collect();
        list.sort_unstable();
        if !list.is_empty() {
            payload.insert(guild_id.get().to_string(), list);
        }
    }

    let json = serde_json::to_string_pretty(&payload)?;
    let tmp_path = path.with_extension("tmp");
    std::fs::write(&tmp_path, json)?;
    std::fs::rename(tmp_path, path)?;
    Ok(())
}

fn load_honeypot_state(path: &PathBuf) -> anyhow::Result<HoneypotState> {
    if !path.exists() {
        info!(
            "Honeypot state file {} not present; starting with empty state.",
            path.display()
        );
        return Ok(HoneypotState::default());
    }

    let data = std::fs::read_to_string(path)?;
    let mut state: HoneypotState = serde_json::from_str(&data).unwrap_or_default();
    state.total_bans = state.total_bans.max(state.recent_bans.len() as u64);
    Ok(state)
}

fn save_honeypot_state(path: &PathBuf, state: &HoneypotState) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(state)?;
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
        anyhow::bail!("MONITORED_CHANNEL_ID is empty. Set it in your environment or .env file.");
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
    let honeypot_state_file = whitelist_path(
        &env::var("HONEYPOT_STATE_FILE").unwrap_or_else(|_| "honeypot_state.json".to_string()),
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
        honeypot_state_file,
        channel_concurrency,
        max_retries,
        processing_debounce_seconds,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("evilmeme=info"))
        .init();

    let config = Arc::new(build_config()?);
    let whitelist = load_whitelist(&config.whitelist_file)?;
    let honeypot = load_honeypot_state(&config.honeypot_state_file)?;

    let state = Arc::new(SharedState {
        whitelist_role_ids: RwLock::new(whitelist),
        processing_users: Mutex::new(HashSet::new()),
        honeypot: Mutex::new(honeypot),
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

    info!("Starting evil_meme");
    if let Err(err) = client.start().await {
        error!("Bot terminated with error: {err}");
    }

    Ok(())
}
