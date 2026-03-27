#!/usr/bin/env python3
"""
app.py

Notes:

Configuration (environment variables or a .env file):
  - BOT_TOKEN: Discord bot token (required)
  - MONITORED_CHANNEL_ID: The ID of the single channel to watch (required)
  - MOD_LOG_CHANNEL_ID: Optional ID of a channel where moderation actions/logs will be posted
  - WHITELIST_FILE: Optional path to JSON file to persist whitelist (default: whitelist_ids.json)

Commands (prefix commands, require Manage Guild or Administrator):
  - !whitelist add <role_id>
  - !whitelist remove <role_id>
  - !whitelist list
  - !whitelist reload  (re-read whitelist file from disk)

Other notes:
  - The bot requires these guild permissions: BAN_MEMBERS, VIEW_CHANNEL, READ_MESSAGE_HISTORY,
    MANAGE_MESSAGES, and MANAGE_GUILD. This is for commands.
  - The bot's role must be higher than the target user's highest role to ban successfully.
  - Bulk deletes can't remove messages older than 14 days due to Discord API limitations; this bot only targets the last hour.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set

import discord
from discord import HTTPException, Forbidden, NotFound, TextChannel
from discord.ext import commands

# Try to load .env if available
try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:
    pass

# -----------------------
# Configuration
# -----------------------
BOT_TOKEN = os.environ.get("BOT_TOKEN")
MONITORED_CHANNEL_ID = os.environ.get("MONITORED_CHANNEL_ID")
MOD_LOG_CHANNEL_ID = os.environ.get("MOD_LOG_CHANNEL_ID")
WHITELIST_FILE = os.environ.get("WHITELIST_FILE", "whitelist_ids.json")

if not BOT_TOKEN or not MONITORED_CHANNEL_ID:
    raise SystemExit(
        "Please set BOT_TOKEN and MONITORED_CHANNEL_ID environment variables."
    )

MONITORED_CHANNEL_ID = int(MONITORED_CHANNEL_ID)
MOD_LOG_CHANNEL_ID = int(MOD_LOG_CHANNEL_ID) if MOD_LOG_CHANNEL_ID else None

# Concurrency and retry configuration
CHANNEL_CONCURRENCY = int(os.environ.get("CHANNEL_CONCURRENCY", "3"))
DELETE_BATCH_SIZE = 100
MAX_RETRIES = int(os.environ.get("MAX_RETRIES", "5"))
PROCESSING_DEBOUNCE_SECONDS = int(os.environ.get("PROCESSING_DEBOUNCE_SECONDS", "30"))

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("scammer_bye_bye")

# -----------------------
# Bot setup (intents & client)
# -----------------------
intents = discord.Intents.default()
intents.guilds = True
intents.guild_messages = True
intents.message_content = True  # required for text commands
intents.members = True  # needed for banning and role checks

bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)

# Semaphore to limit concurrent scans across channels
channel_semaphore = asyncio.Semaphore(CHANNEL_CONCURRENCY)

# Debounce set to avoid re-processing same user rapidly
_processing_users: Set[int] = set()
_processing_lock = asyncio.Lock()


# -----------------------
# Whitelist persistence
# -----------------------
def _whitelist_path() -> str:
    # If WHITELIST_FILE is an absolute path use it; otherwise store next to this script
    if os.path.isabs(WHITELIST_FILE):
        return WHITELIST_FILE
    # directory of current file
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, WHITELIST_FILE)


def load_whitelist() -> Set[int]:
    """Load whitelist role IDs from JSON file. Returns a set of ints."""
    path = _whitelist_path()
    if not os.path.exists(path):
        log.info("Whitelist file %s not present; starting with empty whitelist.", path)
        return set()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, list):
            log.warning(
                "Whitelist file %s malformed; expected a list. Starting empty.", path
            )
            return set()
        result = set()
        for item in data:
            try:
                result.add(int(item))
            except (TypeError, ValueError):
                log.warning("Ignoring invalid whitelist entry in file: %r", item)
        log.info("Loaded %d whitelisted role IDs from %s", len(result), path)
        return result
    except Exception:
        log.exception(
            "Failed to read whitelist file %s; starting with empty whitelist.", path
        )
        return set()


def save_whitelist(role_ids: Set[int]) -> None:
    """Persist the whitelist set to disk as a JSON list."""
    path = _whitelist_path()
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(sorted(list(role_ids)), fh, indent=2)
        os.replace(tmp, path)
        log.info("Saved %d whitelisted role IDs to %s", len(role_ids), path)
    except Exception:
        log.exception("Failed to save whitelist to %s", path)


# Initialize whitelist
WHITELIST_ROLE_IDS: Set[int] = load_whitelist()


# -----------------------
# Helpers: retry/backoff & deletion
# -----------------------
def utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


async def backoff_retry(
    coro_callable, *args, retries: int = MAX_RETRIES, base_delay: float = 1.0, **kwargs
):
    """
    Run a coroutine with exponential backoff on HTTPException / timeout.
    Returns coroutine result or raises last exception.
    """
    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            return await coro_callable(*args, **kwargs)
        except (HTTPException, asyncio.TimeoutError) as exc:
            last_exc = exc
            delay = base_delay * (2 ** (attempt - 1))
            log.warning(
                "Transient error attempt %d/%d: %s. Backoff %.1fs",
                attempt,
                retries,
                exc,
                delay,
            )
            await asyncio.sleep(delay)
    if last_exc:
        raise last_exc


async def safe_bulk_delete(channel: TextChannel, messages: List[discord.Message]):
    """Attempt to bulk-delete messages with retries; fallback to individual deletes."""
    if not messages:
        return

    # Filter out messages older than 14 days
    two_weeks_ago = utcnow() - timedelta(days=14)
    fresh = [m for m in messages if m.created_at >= two_weeks_ago]

    if not fresh:
        return

    try:
        if len(fresh) == 1:
            await backoff_retry(fresh[0].delete)
            log.debug("Deleted single message %s in %s", fresh[0].id, channel.id)
        else:
            await backoff_retry(channel.delete_messages, fresh)
            log.info("Bulk deleted %d messages in %s", len(fresh), channel.id)
    except Forbidden:
        log.warning("Missing permission to delete messages in channel %s", channel.id)
    except NotFound:
        log.debug("Some messages were already removed when deleting in %s", channel.id)
    except Exception:
        log.exception(
            "Bulk delete failed in %s; falling back to per-message delete", channel.id
        )
        for m in fresh:
            try:
                await backoff_retry(m.delete)
                await asyncio.sleep(0.2)
            except Forbidden:
                log.warning(
                    "Missing permission deleting message %s in %s",
                    getattr(m, "id", "<unknown>"),
                    channel.id,
                )
                break
            except NotFound:
                continue
            except Exception:
                log.exception(
                    "Failed deleting message %s in %s",
                    getattr(m, "id", "<unknown>"),
                    channel.id,
                )


# -----------------------
# Core scanning / moderation
# -----------------------
async def scan_and_delete_for_user(
    guild: discord.Guild, author_id: int, cutoff: datetime
):
    """Scan text channels and delete messages by author after cutoff time."""
    log.info("Starting cleanup for user %s in guild %s", author_id, guild.id)

    async def worker(channel: TextChannel):
        perms = channel.permissions_for(guild.me)
        if not (
            perms.view_channel and perms.read_message_history and perms.manage_messages
        ):
            log.debug("Skipping channel %s due to insufficient permissions", channel.id)
            return

        to_delete: List[discord.Message] = []
        try:
            async for msg in channel.history(
                limit=None, after=cutoff, oldest_first=False
            ):
                # Defensive: normalize created_at to timezone-aware UTC if needed
                msg_created = msg.created_at
                if msg_created.tzinfo is None:
                    msg_created = msg_created.replace(tzinfo=timezone.utc)
                # Ensure message is by the target author and is not older than cutoff.
                # This guards against any mismatch/edge-cases where channel.history(after=...)
                # might not behave as expected.
                if msg.author and msg.author.id == author_id and msg_created >= cutoff:
                    to_delete.append(msg)
                if len(to_delete) >= DELETE_BATCH_SIZE:
                    await safe_bulk_delete(channel, to_delete)
                    to_delete.clear()
                    await asyncio.sleep(0.6)
            if to_delete:
                await safe_bulk_delete(channel, to_delete)
            log.info("Finished scanning channel %s for user %s", channel.id, author_id)
        except Forbidden:
            log.warning("Forbidden scanning channel %s (no permissions).", channel.id)
        except Exception:
            log.exception("Error scanning channel %s", channel.id)

    # Build channel tasks for guild.text_channels
    channels = [c for c in guild.text_channels]
    tasks = []
    for ch in channels:
        await channel_semaphore.acquire()
        task = asyncio.create_task(worker(ch))
        task.add_done_callback(lambda fut: channel_semaphore.release())
        tasks.append(task)

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    log.info("Cleanup completed for user %s", author_id)


# -----------------------
# Bot events & moderation flow
# -----------------------
@bot.event
async def on_ready():
    log.info("Bot ready: %s (ID: %s)", bot.user, bot.user.id)


@bot.event
async def on_message(message: discord.Message):
    # Ensure commands still work
    await bot.process_commands(message)

    # Only handle messages in a guild, not from bots, and only from the monitored channel
    if (
        not message.guild
        or message.author.bot
        or message.channel.id != MONITORED_CHANNEL_ID
    ):
        return

    author_id = message.author.id
    guild = message.guild

    # WHITELIST CHECK: skip if member has any role id in WHITELIST_ROLE_IDS
    try:
        member = (
            message.author
            if isinstance(message.author, discord.Member)
            else guild.get_member(author_id)
        )
        if member:
            member_role_ids = {r.id for r in member.roles}
            if any(rid in WHITELIST_ROLE_IDS for rid in member_role_ids):
                log.info(
                    "User %s (%s) has a whitelisted role; skipping moderation.",
                    member,
                    author_id,
                )
                return
    except Exception:
        log.exception(
            "Failed to evaluate whitelist for user %s; continuing.", author_id
        )

    # Debounce multiple triggers for same user
    async with _processing_lock:
        if author_id in _processing_users:
            log.info(
                "User %s already being processed; ignoring duplicate trigger.",
                author_id,
            )
            return
        _processing_users.add(author_id)

    # Schedule removal from processing set after debounce timeout
    async def _clear_processing(uid: int):
        await asyncio.sleep(PROCESSING_DEBOUNCE_SECONDS)
        async with _processing_lock:
            _processing_users.discard(uid)

    asyncio.create_task(_clear_processing(author_id))

    log.info(
        "Detected message by user %s in monitored channel; starting moderation flow.",
        f"{message.author} ({author_id})",
    )

    # 1) Ban the user
    ban_reason = f"Posted in monitored channel {MONITORED_CHANNEL_ID}"
    try:
        member = guild.get_member(author_id)
        if member:
            await backoff_retry(guild.ban, member, reason=ban_reason)
            log.info("Banned member %s (%s)", member, author_id)
        else:
            await backoff_retry(
                guild.ban, discord.Object(id=author_id), reason=ban_reason
            )
            log.info("Banned user id %s (member object not found)", author_id)
    except Forbidden:
        log.error(
            "Bot lacks permission to ban user %s in guild %s", author_id, guild.id
        )
    except HTTPException as exc:
        log.exception("Failed to ban %s due to HTTP error: %s", author_id, exc)
    except Exception:
        log.exception("Unexpected error while banning %s", author_id)

    # Optional mod log with embed
    if MOD_LOG_CHANNEL_ID:
        try:
            mod_ch = guild.get_channel(MOD_LOG_CHANNEL_ID)
            if mod_ch and mod_ch.permissions_for(guild.me).send_messages:
                embed = discord.Embed(
                    title="Message deleted",
                    color=discord.Color.dark_red(),
                )

                # Add metadata as description
                channel_mention = f"<#{message.channel.id}>"
                description = (
                    f">>> **Channel:** {message.channel.name} ({channel_mention})\n"
                    f"**Message ID:** {message.id}\n"
                    f"**Message author:** {message.author.mention} ({message.author})\n"
                    f"**Message created:** {discord.utils.format_dt(message.created_at, style='R')}"
                )
                embed.description = description

                # Add message content as a field
                embed.add_field(
                    name="Message",
                    value=message.content or "(empty)",
                    inline=False
                )

                # Add attachments/images to the embed
                if message.attachments:
                    # Check for image attachments to display inline
                    image_attachments = [
                        att for att in message.attachments
                        if att.content_type and att.content_type.startswith("image/")
                    ]
                    if image_attachments:
                        # Set first image as embed image
                        embed.set_image(url=image_attachments[0].url)

                    # List all attachments (with URLs) in a field
                    attachment_lines = []
                    for att in message.attachments:
                        if att.content_type:
                            attachment_lines.append(f"[{att.filename}]({att.url}) ({att.content_type})")
                        else:
                            attachment_lines.append(f"[{att.filename}]({att.url})")

                    if attachment_lines:
                        # Truncate to avoid Discord's 1024 char limit for field values
                        attachment_text = "\n".join(attachment_lines)
                        if len(attachment_text) > 1020:
                            attachment_text = attachment_text[:1020] + "..."

                        embed.add_field(
                            name=f"Attachments ({len(attachment_lines)})",
                            value=attachment_text,
                            inline=False
                        )

                # Add user avatar as thumbnail
                embed.set_thumbnail(url=message.author.display_avatar.url)

                # Add timestamp in footer
                embed.timestamp = message.created_at
                embed.set_footer(text=f"User ID: {author_id}")

                await backoff_retry(mod_ch.send, embed=embed)
        except Exception:
            log.exception("Failed to send mod-log message.")

    # 2) Delete messages from last hour
    cutoff = utcnow() - timedelta(hours=1)
    try:
        await scan_and_delete_for_user(guild, author_id, cutoff)
    except Exception:
        log.exception("Error while scanning/deleting messages for %s", author_id)

    log.info("Moderation flow finished for user %s", author_id)


# -----------------------
# Runtime whitelist management commands
# -----------------------
def moderator_check(ctx: commands.Context) -> bool:
    """Simple check: user must have manage_guild or administrator."""
    perms = ctx.author.guild_permissions
    return perms.manage_guild or perms.administrator


@bot.group(name="whitelist", invoke_without_command=True)
@commands.check(moderator_check)
async def whitelist_group(ctx: commands.Context):
    """Whitelist management group. Use subcommands add/remove/list/reload."""
    await ctx.send(
        "Usage: `!whitelist add <role_id>`, `!whitelist remove <role_id>`, `!whitelist list`, `!whitelist reload`"
    )


@whitelist_group.command(name="add")
@commands.check(moderator_check)
async def whitelist_add(ctx: commands.Context, role_id: int):
    """Add a role ID to the whitelist."""
    if role_id in WHITELIST_ROLE_IDS:
        await ctx.send(f"Role ID {role_id} is already whitelisted.")
        return
    WHITELIST_ROLE_IDS.add(role_id)
    save_whitelist(WHITELIST_ROLE_IDS)
    # Try to resolve role to a name for nicer feedback
    role_name = None
    try:
        role = ctx.guild.get_role(role_id)
        if role:
            role_name = role.name
    except Exception:
        role_name = None
    if role_name:
        await ctx.send(f"Added role `{role_name}` ({role_id}) to whitelist.")
    else:
        await ctx.send(
            f"Added role ID `{role_id}` to whitelist (role not found on this guild)."
        )


@whitelist_group.command(name="remove")
@commands.check(moderator_check)
async def whitelist_remove(ctx: commands.Context, role_id: int):
    """Remove a role ID from the whitelist."""
    if role_id not in WHITELIST_ROLE_IDS:
        await ctx.send(f"Role ID {role_id} is not in the whitelist.")
        return
    WHITELIST_ROLE_IDS.discard(role_id)
    save_whitelist(WHITELIST_ROLE_IDS)
    await ctx.send(f"Removed role ID `{role_id}` from whitelist.")


@whitelist_group.command(name="list")
@commands.check(moderator_check)
async def whitelist_list(ctx: commands.Context):
    """List whitelisted role IDs (try to resolve names if possible)."""
    if not WHITELIST_ROLE_IDS:
        await ctx.send("Whitelist is empty.")
        return
    lines = []
    for rid in sorted(WHITELIST_ROLE_IDS):
        try:
            role = ctx.guild.get_role(rid)
            if role:
                lines.append(f"`{rid}` — {role.name}")
            else:
                lines.append(f"`{rid}` — (not present in this guild)")
        except Exception:
            lines.append(f"`{rid}`")
    # Send in chunks if long
    chunk = "\n".join(lines)
    await ctx.send(f"Whitelisted role IDs:\n{chunk}")


@whitelist_group.command(name="reload")
@commands.check(moderator_check)
async def whitelist_reload(ctx: commands.Context):
    """Reload the whitelist from disk (useful if the file was edited manually)."""
    global WHITELIST_ROLE_IDS
    WHITELIST_ROLE_IDS = load_whitelist()
    await ctx.send(f"Reloaded whitelist from disk: {len(WHITELIST_ROLE_IDS)} role IDs.")


# Error handlers for command checks
@whitelist_group.error
async def whitelist_group_error(ctx: commands.Context, error):
    if isinstance(error, commands.CheckFailure):
        await ctx.send("You do not have permission to manage the whitelist.")
    else:
        log.exception("Error in whitelist command: %s", error)
        await ctx.send("An error occurred while running the whitelist command.")


# -----------------------
# Run
# -----------------------
def main():
    log.info("Starting scammer_bye_bye bot")
    try:
        bot.run(BOT_TOKEN)
    except Exception:
        log.exception("Bot terminated with exception")


if __name__ == "__main__":
    main()
