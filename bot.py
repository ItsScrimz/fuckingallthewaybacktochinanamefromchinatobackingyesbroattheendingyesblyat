import discord
from discord.ext import commands
import asyncio
import datetime
import html
import json
import logging
import os
import re
import secrets
import string
from collections import defaultdict, deque
from pathlib import Path
from urllib.parse import quote, quote_plus, urlparse

import aiohttp
from aiohttp import web
import pytz

import security_config as sc

# ── Load .env file if present (local dev). On Render the vars are set in the
#    dashboard and python-dotenv simply finds nothing to load — no side effects.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ModuleNotFoundError:
    pass   # dotenv not installed → already running with real env vars (Render)

# ── Configuration (from .env locally, from Render dashboard in production) ────
TOKEN         = os.environ["DISCORD_TOKEN"]
CLIENT_ID     = os.environ["DISCORD_CLIENT_ID"]
CLIENT_SECRET = os.environ["DISCORD_CLIENT_SECRET"]
REDIRECT_URI  = os.environ["REDIRECT_URI"]    # https://yourapp.onrender.com/auth
PREFIX        = os.environ.get("PREFIX", ",")

# Render assigns the port via $PORT; we always bind to 0.0.0.0
OAUTH_HOST    = "0.0.0.0"
OAUTH_PORT    = int(os.environ.get("PORT", 8080))

# ── File logger ────────────────────────────────────────────────────────────────
# Render's filesystem is ephemeral — /tmp is writable and persists for the session
LOG_FILE = Path("/tmp/bot.log")

_log_fmt  = logging.Formatter(
    "[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
_file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
_file_handler.setFormatter(_log_fmt)

_console_handler = logging.StreamHandler()
_console_handler.setFormatter(_log_fmt)

logger = logging.getLogger("bot")
logger.setLevel(logging.INFO)
logger.addHandler(_file_handler)
logger.addHandler(_console_handler)

# ── In-memory stores ───────────────────────────────────────────────────────────
afk_users: dict[int, tuple[str, datetime.datetime]] = {}   # user_id -> (reason, timestamp)

# ── OAuth2 Authenticator state ─────────────────────────────────────────────────
# oauth_states : { state_token -> {"guild_id": int, "user_id": int, "expires": datetime} }
# verified     : { guild_id -> {user_id -> verified_at_iso} }   (kept in data.json)
oauth_states: dict[str, dict] = {}

OAUTH_STATE_EXPIRY   = 600        # seconds before an OAuth state token expires (10 min)
AUTH_VERIFY_ROLE     = "verified"   # role granted on success (case-insensitive)
AUTH_UNVERIFIED_ROLE = "unverified" # role stripped on success (set "" to skip)

DISCORD_OAUTH_URL  = "https://discord.com/oauth2/authorize"
DISCORD_TOKEN_URL  = "https://discord.com/api/v10/oauth2/token"
DISCORD_ME_URL     = "https://discord.com/api/v10/users/@me"

# ── Persistent store (survives restarts) ───────────────────────────────────────
# timezones : { user_id: {"tz": "Asia/Kolkata", "place": "Hyderabad"} }
# hardbans  : { guild_id: [user_id, ...] }
# jailed    : { guild_id: { user_id: [saved_role_id, ...] } }
# lockdowns : { guild_id: {"channels": {channel_id: {perm: value}}, "invites_were_paused": bool} }
# Render's filesystem is ephemeral; /tmp is writable for the life of the instance.
# Data WILL be lost on redeploy/restart — this is a free-plan limitation.
# For persistence across restarts, use a database (e.g. Render Postgres or Redis).
DATA_FILE = Path("/tmp/data.json")


def load_data() -> dict:
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            loaded = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        loaded = {}
    for key in ("timezones", "hardbans", "jailed", "lockdowns", "security", "warnings", "verified"):
        loaded.setdefault(key, {})
    return loaded


def save_data() -> None:
    tmp = DATA_FILE.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, DATA_FILE)


data = load_data()

# ── Admin roles ────────────────────────────────────────────────────────────────
# Members with ANY of these roles can use every moderation command.
# The server owner and anyone with the Administrator permission always can.
# Names are matched ignoring capitals and spaces ("+authority" = "+ Authority").
ADMIN_ROLE_NAMES = [
    "+ authority",   # both roles with this name count
    "min",
    "wadha",
    "^ staff",
    "^ mods",
]


def _norm(name: str) -> str:
    return "".join(name.split()).lower()


def is_admin():
    async def predicate(ctx: commands.Context) -> bool:
        if ctx.guild is None:
            raise commands.NoPrivateMessage()
        author = ctx.author
        if author.id == ctx.guild.owner_id or author.guild_permissions.administrator:
            return True
        if author.id in {int(i) for i in sc.SECURITY_USER_IDS}:
            return True
        wanted = {_norm(n) for n in ADMIN_ROLE_NAMES}
        if any(_norm(r.name) in wanted for r in author.roles):
            return True
        raise commands.CheckFailure("🚫 Only admins can use that command.")
    return commands.check(predicate)


JAIL_ROLE_NAME    = "jailed"   # matched case-insensitively, so "Jailed" also works
JAIL_CHANNEL_NAME = "jail"


def find_jail_role(guild: discord.Guild) -> discord.Role | None:
    return discord.utils.find(lambda r: r.name.lower() == JAIL_ROLE_NAME, guild.roles)


def find_jail_channel(guild: discord.Guild) -> discord.TextChannel | None:
    return discord.utils.find(lambda c: c.name.lower() == JAIL_CHANNEL_NAME, guild.text_channels)

# ── Bot setup ──────────────────────────────────────────────────────────────────
intents = discord.Intents.default()
intents.message_content = True
intents.members = True

bot = commands.Bot(command_prefix=PREFIX, intents=intents)


# ── Helpers ────────────────────────────────────────────────────────────────────

def format_duration(seconds: float) -> str:
    """Convert seconds into a human-readable duration string."""
    seconds = int(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    mins, secs = divmod(rem, 60)
    parts = []
    if days:  parts.append(f"{days}d")
    if hours: parts.append(f"{hours}h")
    if mins:  parts.append(f"{mins}m")
    if secs or not parts:
        parts.append(f"{secs}s")
    return " ".join(parts)


INVITE_RE = re.compile(r"(discord\.gg|discord(?:app)?\.com/invite|dsc\.gg)/\S+", re.IGNORECASE)

_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_duration(text: str) -> datetime.timedelta | None:
    """Parse '10m', '2h', '1d12h', '1w' etc. Returns None if it isn't a duration."""
    text = text.strip().lower()
    if not re.fullmatch(r"(\d+[smhdw])+", text):
        return None
    seconds = sum(int(n) * _DURATION_UNITS[u] for n, u in re.findall(r"(\d+)([smhdw])", text))
    return datetime.timedelta(seconds=seconds) if seconds > 0 else None


def hierarchy_error(ctx: commands.Context, member: discord.Member) -> str | None:
    """Return an error message if the invoker/bot can't moderate this member, else None."""
    guild = ctx.guild
    if member.id == ctx.author.id:
        return "❌ You can't do that to yourself."
    if member.id == guild.me.id:
        return "❌ I can't do that to myself."
    if member.id == guild.owner_id:
        return "❌ You can't do that to the server owner."
    if ctx.author.id != guild.owner_id and member.top_role >= ctx.author.top_role:
        return "❌ That member's top role is equal to or higher than yours."
    if member.top_role >= guild.me.top_role:
        return "❌ That member's top role is higher than mine — move my role up in Server Settings → Roles."
    return None


async def resolve_member(guild: discord.Guild, query: str) -> discord.Member | discord.User | None:
    """
    Resolve a member from a user ID, @mention, username, or display name.
    Returns a Member if found in the guild, a User if only found via API, or None.
    """
    query = query.strip().lstrip("<@!").rstrip(">")

    # Try as ID first
    if query.isdigit():
        uid = int(query)
        member = guild.get_member(uid)
        if member:
            return member
        try:
            return await guild.fetch_member(uid)
        except discord.NotFound:
            pass
        try:
            return await guild.me._state.http.get_user(uid) and await guild.me._state.client.fetch_user(uid)
        except Exception:
            return None

    # Try by username or display name (case-insensitive)
    query_lower = query.lower()
    for member in guild.members:
        if member.name.lower() == query_lower or member.display_name.lower() == query_lower:
            return member

    return None


# ── Events ─────────────────────────────────────────────────────────────────────

@bot.event
async def on_ready():
    logger.info(f"[READY] Logged in as {bot.user} (ID: {bot.user.id}) | "
                f"Guilds: {len(bot.guilds)} | Prefix: {PREFIX!r}")
    print(f"Logged in as {bot.user} (ID: {bot.user.id})")
    await bot.change_presence(activity=discord.Game(name=f"{PREFIX}help"))


@bot.event
async def on_member_join(member: discord.Member):
    gid, uid = str(member.guild.id), member.id

    logger.info(f"[JOIN] user={member} (id={member.id}) | guild={member.guild.name!r} (id={member.guild.id}) "
                f"| account_age={format_duration((discord.utils.utcnow() - member.created_at).total_seconds())}")

    # Hardbanned user somehow got back in → ban again
    if uid in data["hardbans"].get(gid, []):
        logger.info(f"[JOIN] Hardbanned user rejoined — rebanning: user={member} (id={member.id})")
        try:
            await member.guild.ban(member, reason="Hardban — cannot be lifted")
        except discord.HTTPException:
            pass
        return

    # Security: account-age check + raid detection
    if await security_on_join(member):
        return

    e = log_embed("📥 Member Joined", discord.Color.green())
    e.set_thumbnail(url=member.display_avatar.url)
    e.add_field(name="👤 User", value=who(member), inline=True)
    e.add_field(name="📆 Account Age",
                value=format_duration((discord.utils.utcnow() - member.created_at).total_seconds()), inline=True)
    await send_log(member.guild, e)

    # ── Start auth: send OAuth2 verification link via DM ─────────────────────────
    gid_data = data["verified"].get(gid, {})
    if str(uid) not in gid_data:           # skip if already verified (e.g. rejoin)
        sent = await start_auth(member)
        if not sent:
            # DMs closed — notify in log channel so admins can resend manually
            dm_fail_embed = log_embed(
                "🔐 Auth DM Failed",
                discord.Color.orange(),
                f"{member.mention} joined but has DMs closed — verification link could not be delivered.\n"
                f"Use `,auth resend {member.mention}` to retry once they open DMs."
            )
            await send_log(member.guild, dm_fail_embed)
    else:
        _auth_log("rejoin_already_verified", user=member, guild=member.guild)

    # Jailed user left and rejoined → put them straight back in jail
    if str(uid) in data["jailed"].get(gid, {}):
        role = find_jail_role(member.guild)
        if role:
            try:
                await member.add_roles(role, reason="Rejoined while jailed")
            except discord.HTTPException:
                pass
        return

    if member.guild.system_channel:
        await member.guild.system_channel.send(
            f"👋 Welcome to **{member.guild.name}**, {member.mention}!"
        )


@bot.event
async def on_message(message: discord.Message):
    # Ignore bot messages
    if message.author.bot:
        return

    # ── Security auto-mod (spam, pings, links) ────────────────────────────────
    if await run_automod(message):
        return

    # ── Lockdown: block invite links from non-mods ────────────────────────────
    if (
        message.guild
        and str(message.guild.id) in data["lockdowns"]
        and INVITE_RE.search(message.content)
        and not message.author.guild_permissions.manage_messages
    ):
        automod_deleted.add(message.id)
        try:
            await message.delete()
            await message.channel.send(
                f"🔒 {message.author.mention} invite links are blocked during lockdown.",
                delete_after=5,
            )
        except discord.HTTPException:
            pass
        return

    # ── AFK: remove AFK when the user speaks ──────────────────────────────────
    if message.author.id in afk_users:
        reason, since = afk_users.pop(message.author.id)
        duration = (datetime.datetime.utcnow() - since).total_seconds()
        await message.channel.send(
            f"👋 Welcome back, {message.author.mention}! "
            f"You were AFK for **{format_duration(duration)}**."
        )

    # ── AFK: notify when someone pings an AFK user ────────────────────────────
    for mentioned in message.mentions:
        if mentioned.id in afk_users:
            reason, since = afk_users[mentioned.id]
            duration = (datetime.datetime.utcnow() - since).total_seconds()
            await message.channel.send(
                f"💤 **{mentioned.display_name}** is AFK: *{reason}* "
                f"(gone for {format_duration(duration)})"
            )

    await bot.process_commands(message)


@bot.event
async def on_member_remove(member: discord.Member):
    logger.info(f"[LEAVE] user={member} (id={member.id}) | guild={member.guild.name!r} (id={member.guild.id})")
    # Clean up any pending auth code for someone who left before verifying
    # Clean up any pending OAuth states for someone who left before verifying
    stale = [s for s, v in oauth_states.items() if v.get("user_id") == member.id]
    for st in stale:
        oauth_states.pop(st, None)
    if stale:
        _auth_log("pending_cleared_on_leave", user=member, guild=member.guild)


@bot.event
async def on_member_unban(guild: discord.Guild, user: discord.User):
    # Anyone who unbans a hardbanned user (even manually in Server Settings) gets reverted
    if user.id in data["hardbans"].get(str(guild.id), []):
        try:
            await guild.ban(user, reason="Hardban — cannot be lifted")
        except discord.HTTPException:
            pass


@bot.event
async def on_guild_channel_create(channel: discord.abc.GuildChannel):
    # New channels stay hidden from the jail role
    role = find_jail_role(channel.guild)
    if role and channel.name != JAIL_CHANNEL_NAME:
        try:
            await channel.set_permissions(role, view_channel=False, reason="Hide from jailed members")
        except discord.HTTPException:
            pass


@bot.event
async def on_command_error(ctx: commands.Context, error: commands.CommandError):
    guild_str = f"guild={ctx.guild.name!r} (id={ctx.guild.id})" if ctx.guild else "DM"
    logger.warning(
        f"[CMD_ERROR] cmd={ctx.command} | user={ctx.author} (id={ctx.author.id}) | "
        f"{guild_str} | error={type(error).__name__}: {error}"
    )
    if isinstance(error, commands.CommandNotFound):
        await ctx.send("❓ Unknown command. Try `,help`.")
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(f"⚠️ Missing argument: `{error.param.name}`.")
    elif isinstance(error, commands.MissingPermissions):
        await ctx.send("🚫 You don't have permission to do that.")
    elif isinstance(error, commands.BadArgument):
        await ctx.send(f"⚠️ Bad argument: {error}")
    elif isinstance(error, commands.CommandOnCooldown):
        await ctx.send(f"⏳ Slow down — try again in **{error.retry_after:.1f}s**.", delete_after=5)
    elif isinstance(error, commands.NoPrivateMessage):
        await ctx.send("⚠️ That command only works inside a server.")
    elif isinstance(error, commands.CheckFailure):
        await ctx.send(str(error) or "🚫 You can't use that command.")
    else:
        await ctx.send(f"❌ Error: {error}")
        raise error


@bot.event
async def on_command(ctx: commands.Context):
    """Log every successfully-invoked command."""
    guild_str = f"guild={ctx.guild.name!r} (id={ctx.guild.id})" if ctx.guild else "DM"
    logger.info(
        f"[CMD] cmd={ctx.command} | user={ctx.author} (id={ctx.author.id}) | "
        f"{guild_str} | args={ctx.args[2:]!r} | kwargs={ctx.kwargs!r}"
    )


# ══════════════════════════════════════════════════════════════════════════════
# GENERAL COMMANDS
# ══════════════════════════════════════════════════════════════════════════════

@bot.command(name="ping")
async def ping(ctx: commands.Context):
    """Check bot latency."""
    latency = round(bot.latency * 1000)
    await ctx.send(f"🏓 Pong! Latency: **{latency} ms**")


@bot.command(name="say")
@is_admin()
async def say(ctx: commands.Context, *, message: str):
    """Make the bot repeat a message.  Usage: ,say <text>"""
    await ctx.message.delete()
    await ctx.send(message)


# ══════════════════════════════════════════════════════════════════════════════
# BATCH 1 — afk · avatar
# ══════════════════════════════════════════════════════════════════════════════

@bot.command(name="afk")
async def afk(ctx: commands.Context, *, reason: str = "AFK"):
    """Set yourself as AFK.  Usage: ,afk [reason]"""
    afk_users[ctx.author.id] = (reason, datetime.datetime.utcnow())
    await ctx.send(f"💤 {ctx.author.mention} is now AFK: *{reason}*")


@bot.command(name="avatar")
async def avatar(ctx: commands.Context, member: discord.Member = None):
    """Show a user's avatar.  Usage: ,avatar [@user]"""
    member = member or ctx.author
    embed = discord.Embed(
        title=f"{member.display_name}'s Avatar",
        color=discord.Color.blurple()
    )
    embed.set_image(url=member.display_avatar.url)
    embed.set_footer(text=f"Requested by {ctx.author.display_name}")
    await ctx.send(embed=embed)


# ══════════════════════════════════════════════════════════════════════════════
# BATCH 2 — banner · bans · color
# ══════════════════════════════════════════════════════════════════════════════

@bot.command(name="banner")
async def banner(ctx: commands.Context, member: discord.Member = None):
    """Show a user's profile banner.  Usage: ,banner [@user]"""
    member = member or ctx.author
    # Need to fetch the full user object to get banner
    user = await bot.fetch_user(member.id)
    if not user.banner:
        await ctx.send(f"❌ **{member.display_name}** doesn't have a banner set.")
        return
    embed = discord.Embed(
        title=f"{member.display_name}'s Banner",
        color=discord.Color.blurple()
    )
    embed.set_image(url=user.banner.url)
    embed.set_footer(text=f"Requested by {ctx.author.display_name}")
    await ctx.send(embed=embed)


@bot.command(name="bans")
@is_admin()
async def bans(ctx: commands.Context):
    """List all bans in the server.  Usage: ,bans"""
    ban_list = [entry async for entry in ctx.guild.bans()]
    if not ban_list:
        await ctx.send("✅ No bans on this server.")
        return

    # Paginate into chunks of 10 per embed field
    chunk_size = 10
    chunks = [ban_list[i:i + chunk_size] for i in range(0, len(ban_list), chunk_size)]
    embed = discord.Embed(
        title=f"🔨 Server Bans — {len(ban_list)} total",
        color=discord.Color.red()
    )
    for i, chunk in enumerate(chunks[:25]):  # Discord embed field limit = 25
        lines = "\n".join(
            f"`{entry.user}` (ID: `{entry.user.id}`) — {entry.reason or 'No reason'}"
            for entry in chunk
        )
        embed.add_field(name=f"Bans {i * chunk_size + 1}–{i * chunk_size + len(chunk)}", value=lines, inline=False)
    await ctx.send(embed=embed)


@bot.command(name="color")
async def color(ctx: commands.Context, hex_code: str):
    """Preview a hex color.  Usage: ,color <#RRGGBB>"""
    hex_code = hex_code.lstrip("#")
    if len(hex_code) != 6:
        await ctx.send("⚠️ Please provide a valid 6-digit hex code, e.g. `,color #FF5733`")
        return
    try:
        int_color = int(hex_code, 16)
    except ValueError:
        await ctx.send("⚠️ Invalid hex code. Example: `,color #FF5733`")
        return

    r = int(hex_code[0:2], 16)
    g = int(hex_code[2:4], 16)
    b = int(hex_code[4:6], 16)

    embed = discord.Embed(
        title=f"Color — #{hex_code.upper()}",
        description=f"**RGB:** ({r}, {g}, {b})\n**Hex:** `#{hex_code.upper()}`",
        color=int_color
    )
    # Use a color swatch image from a free API (no auth needed)
    embed.set_thumbnail(url=f"https://singlecolorimage.com/get/{hex_code}/100x100")
    await ctx.send(embed=embed)


# ══════════════════════════════════════════════════════════════════════════════
# BATCH 3 — serveravatar · serverbanner · serverinfo
# ══════════════════════════════════════════════════════════════════════════════

@bot.command(name="serveravatar")
async def serveravatar(ctx: commands.Context, member: discord.Member = None):
    """Show a member's server-specific avatar (Nitro).  Usage: ,serveravatar [@user]"""
    member = member or ctx.author

    # guild_avatar is their server-specific one (Nitro perk); falls back to global
    server_av = member.guild_avatar
    global_av  = member.avatar or member.default_avatar

    if server_av:
        embed = discord.Embed(
            title=f"{member.display_name}'s Server Avatar",
            color=discord.Color.blurple()
        )
        embed.set_image(url=server_av.url)
        embed.set_footer(text=f"This is their Nitro server-specific avatar • Requested by {ctx.author.display_name}")
    else:
        # They have no server avatar — show their global one and say so
        embed = discord.Embed(
            title=f"{member.display_name}'s Avatar",
            description="This member hasn't set a server-specific avatar. Showing their global avatar.",
            color=discord.Color.blurple()
        )
        embed.set_image(url=global_av.url)
        embed.set_footer(text=f"Requested by {ctx.author.display_name}")

    await ctx.send(embed=embed)


@bot.command(name="serverbanner")
async def serverbanner(ctx: commands.Context, member: discord.Member = None):
    """Show the server banner, or a user's profile banner.  Usage: ,serverbanner [@user]"""

    # If a member is mentioned, show their profile banner
    if member:
        user = await bot.fetch_user(member.id)
        if not user.banner:
            await ctx.send(f"❌ **{member.display_name}** doesn't have a profile banner set.")
            return
        embed = discord.Embed(
            title=f"{member.display_name}'s Banner",
            color=discord.Color.blurple()
        )
        embed.set_image(url=user.banner.url)
        embed.set_footer(text=f"Requested by {ctx.author.display_name}")
        await ctx.send(embed=embed)
        return

    # No member mentioned — show the server banner
    guild = ctx.guild
    if not guild.banner:
        await ctx.send("❌ This server doesn't have a banner set.")
        return
    embed = discord.Embed(
        title=f"{guild.name}'s Server Banner",
        color=discord.Color.blurple()
    )
    embed.set_image(url=guild.banner.url)
    embed.set_footer(text=f"Requested by {ctx.author.display_name}")
    await ctx.send(embed=embed)


@bot.command(name="serverinfo")
async def serverinfo(ctx: commands.Context):
    """Show detailed information about the server.  Usage: ,serverinfo"""
    guild = ctx.guild

    # Count channel types
    text_channels     = len(guild.text_channels)
    voice_channels    = len(guild.voice_channels)
    stage_channels    = len(guild.stage_channels)
    category_channels = len(guild.categories)
    forum_channels    = len(guild.forums) if hasattr(guild, "forums") else 0

    # Count member types
    total_members  = guild.member_count
    bots           = sum(1 for m in guild.members if m.bot)
    humans         = total_members - bots

    # Boost info
    boost_level = guild.premium_tier
    boost_count = guild.premium_subscription_count or 0

    # Verification level
    verification = str(guild.verification_level).replace("_", " ").title()

    embed = discord.Embed(
        title=guild.name,
        description=guild.description or "",
        color=discord.Color.blurple(),
        timestamp=datetime.datetime.utcnow()
    )
    if guild.icon:
        embed.set_thumbnail(url=guild.icon.url)
    if guild.banner:
        embed.set_image(url=guild.banner.url)

    embed.add_field(name="👑 Owner",         value=guild.owner.mention,                          inline=True)
    embed.add_field(name="🪪 Server ID",     value=f"`{guild.id}`",                              inline=True)
    embed.add_field(name="📅 Created",       value=guild.created_at.strftime("%d %b %Y"),        inline=True)

    embed.add_field(name="👥 Members",       value=f"**{humans}** humans • **{bots}** bots",     inline=True)
    embed.add_field(name="🚀 Boosts",        value=f"Level **{boost_level}** • **{boost_count}** boosts", inline=True)
    embed.add_field(name="🔒 Verification",  value=verification,                                 inline=True)

    embed.add_field(
        name="💬 Channels",
        value=(
            f"📝 **{text_channels}** text • 🔊 **{voice_channels}** voice\n"
            f"🎭 **{stage_channels}** stage • 🗂️ **{category_channels}** categories"
            + (f" • 💬 **{forum_channels}** forums" if forum_channels else "")
        ),
        inline=False
    )
    embed.add_field(name="🎭 Roles",         value=f"**{len(guild.roles)}** roles",               inline=True)
    embed.add_field(name="😀 Emojis",        value=f"**{len(guild.emojis)}** / {guild.emoji_limit}", inline=True)
    embed.add_field(name="🖼️ Stickers",     value=f"**{len(guild.stickers)}**",                 inline=True)

    embed.set_footer(text=f"Requested by {ctx.author.display_name}")
    await ctx.send(embed=embed)


# ══════════════════════════════════════════════════════════════════════════════
# MODERATION — modals & confirmation views
# ══════════════════════════════════════════════════════════════════════════════

def mod_result_embed(
    title: str,
    color: discord.Color,
    target: discord.Member | discord.User,
    moderator: discord.Member,
    reason: str,
    extra_fields: list[tuple[str, str, bool]] = [],
) -> discord.Embed:
    """Build a rich moderation result embed."""
    now = datetime.datetime.utcnow().strftime("%d %b %Y • %H:%M UTC")
    embed = discord.Embed(title=title, color=color, timestamp=datetime.datetime.utcnow())
    embed.set_thumbnail(url=target.display_avatar.url)
    embed.add_field(name="👤 User",        value=f"{target.mention}\n`{target}`",          inline=True)
    embed.add_field(name="🪪 User ID",     value=f"`{target.id}`",                         inline=True)
    embed.add_field(name="\u200b",         value="\u200b",                                 inline=True)  # spacer
    embed.add_field(name="🛡️ Moderator",  value=f"{moderator.mention}\n`{moderator}`",    inline=True)
    embed.add_field(name="🪪 Mod ID",      value=f"`{moderator.id}`",                      inline=True)
    embed.add_field(name="\u200b",         value="\u200b",                                 inline=True)  # spacer
    for name, value, inline in extra_fields:
        embed.add_field(name=name, value=value, inline=inline)
    embed.add_field(name="📋 Reason",      value=reason,                                   inline=False)
    embed.set_footer(text=f"Action taken on {now}")
    return embed


# ── Kick ──────────────────────────────────────────────────────────────────────

class KickModal(discord.ui.Modal, title="Kick Member"):
    reason = discord.ui.TextInput(
        label="Reason",
        placeholder="Why are you kicking this member?",
        required=False,
        max_length=512,
        style=discord.TextStyle.paragraph,
    )

    def __init__(self, member: discord.Member, moderator: discord.Member):
        super().__init__()
        self.member = member
        self.moderator = moderator

    async def on_submit(self, interaction: discord.Interaction):
        reason = self.reason.value or "No reason provided"
        try:
            await self.member.kick(reason=f"{reason} (by {self.moderator})")
        except discord.Forbidden:
            await interaction.response.send_message("❌ I don't have permission to kick that member.", ephemeral=True)
            return
        embed = mod_result_embed(
            title="👢 Member Kicked",
            color=discord.Color.orange(),
            target=self.member,
            moderator=self.moderator,
            reason=reason,
        )
        await interaction.response.edit_message(embed=embed, view=None)


class KickConfirmView(discord.ui.View):
    def __init__(self, member: discord.Member, moderator: discord.Member):
        super().__init__(timeout=60)
        self.member = member
        self.moderator = moderator

    @discord.ui.button(label="Enter Reason & Kick", style=discord.ButtonStyle.danger, emoji="👢")
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.moderator.id:
            await interaction.response.send_message("❌ Only the command invoker can do this.", ephemeral=True)
            return
        await interaction.response.send_modal(KickModal(self.member, self.moderator))
        self.stop()

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary, emoji="✖️")
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.moderator.id:
            await interaction.response.send_message("❌ Only the command invoker can do this.", ephemeral=True)
            return
        await interaction.response.edit_message(content="❌ Kick cancelled.", embed=None, view=None)
        self.stop()


@bot.command(name="kick")
@is_admin()
async def kick(ctx: commands.Context, member: discord.Member):
    """Kick a member.  Usage: ,kick @user"""
    embed = discord.Embed(title="👢 Kick Confirmation", color=discord.Color.orange())
    embed.set_thumbnail(url=member.display_avatar.url)
    embed.add_field(name="👤 Target",  value=f"{member.mention} `{member}`", inline=True)
    embed.add_field(name="🪪 User ID", value=f"`{member.id}`",               inline=True)
    embed.add_field(name="📅 Joined",  value=member.joined_at.strftime("%d %b %Y") if member.joined_at else "Unknown", inline=True)
    embed.set_footer(text=f"Requested by {ctx.author.display_name}")
    await ctx.send(embed=embed, view=KickConfirmView(member, ctx.author))


# ── Ban ───────────────────────────────────────────────────────────────────────

class BanModal(discord.ui.Modal, title="Ban Member"):
    reason = discord.ui.TextInput(
        label="Reason",
        placeholder="Why are you banning this member?",
        required=False,
        max_length=512,
        style=discord.TextStyle.paragraph,
    )
    delete_days = discord.ui.TextInput(
        label="Delete message history (days, 0–7)",
        placeholder="0",
        required=False,
        max_length=1,
    )

    def __init__(self, member: discord.Member, moderator: discord.Member):
        super().__init__()
        self.member = member
        self.moderator = moderator

    async def on_submit(self, interaction: discord.Interaction):
        reason = self.reason.value or "No reason provided"
        try:
            days = max(0, min(7, int(self.delete_days.value or 0)))
        except ValueError:
            days = 0
        try:
            await self.member.ban(reason=f"{reason} (by {self.moderator})", delete_message_days=days)
        except discord.Forbidden:
            await interaction.response.send_message("❌ I don't have permission to ban that member.", ephemeral=True)
            return
        embed = mod_result_embed(
            title="🔨 Member Banned",
            color=discord.Color.red(),
            target=self.member,
            moderator=self.moderator,
            reason=reason,
            extra_fields=[
                ("🗑️ Messages Deleted", f"Last **{days}** day(s) wiped" if days else "None deleted", True),
            ],
        )
        await interaction.response.edit_message(embed=embed, view=None)


class BanConfirmView(discord.ui.View):
    def __init__(self, member: discord.Member, moderator: discord.Member):
        super().__init__(timeout=60)
        self.member = member
        self.moderator = moderator

    @discord.ui.button(label="Enter Reason & Ban", style=discord.ButtonStyle.danger, emoji="🔨")
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.moderator.id:
            await interaction.response.send_message("❌ Only the command invoker can do this.", ephemeral=True)
            return
        await interaction.response.send_modal(BanModal(self.member, self.moderator))
        self.stop()

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary, emoji="✖️")
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.moderator.id:
            await interaction.response.send_message("❌ Only the command invoker can do this.", ephemeral=True)
            return
        await interaction.response.edit_message(content="❌ Ban cancelled.", embed=None, view=None)
        self.stop()


@bot.command(name="ban")
@is_admin()
async def ban(ctx: commands.Context, member: discord.Member):
    """Ban a member.  Usage: ,ban @user"""
    embed = discord.Embed(title="🔨 Ban Confirmation", color=discord.Color.red())
    embed.set_thumbnail(url=member.display_avatar.url)
    embed.add_field(name="👤 Target",   value=f"{member.mention} `{member}`", inline=True)
    embed.add_field(name="🪪 User ID",  value=f"`{member.id}`",               inline=True)
    embed.add_field(name="📅 Joined",   value=member.joined_at.strftime("%d %b %Y") if member.joined_at else "Unknown", inline=True)
    embed.add_field(name="📆 Account",  value=member.created_at.strftime("%d %b %Y"), inline=True)
    embed.add_field(name="🎭 Top Role", value=member.top_role.mention,        inline=True)
    embed.set_footer(text=f"Requested by {ctx.author.display_name}")
    await ctx.send(embed=embed, view=BanConfirmView(member, ctx.author))


# ── Unban ─────────────────────────────────────────────────────────────────────

@bot.command(name="unban")
@is_admin()
async def unban(ctx: commands.Context, user_id: int):
    """Unban a user by their ID.  Usage: ,unban <user_id>"""
    if user_id in data["hardbans"].get(str(ctx.guild.id), []):
        await ctx.send("⛔ That user is **hardbanned**. A hardban cannot be lifted.")
        return
    try:
        user = await bot.fetch_user(user_id)
    except discord.NotFound:
        await ctx.send(f"❌ No user found with ID `{user_id}`.")
        return
    try:
        await ctx.guild.unban(user)
        embed = discord.Embed(title="✅ User Unbanned", color=discord.Color.green())
        embed.set_thumbnail(url=user.display_avatar.url)
        embed.add_field(name="👤 User",       value=f"`{user}`",        inline=True)
        embed.add_field(name="🪪 User ID",    value=f"`{user.id}`",     inline=True)
        embed.add_field(name="🛡️ Unbanned by", value=f"{ctx.author.mention}", inline=True)
        embed.set_footer(text=datetime.datetime.utcnow().strftime("%d %b %Y • %H:%M UTC"))
        await ctx.send(embed=embed)
    except discord.NotFound:
        await ctx.send(f"❌ **{user}** is not banned on this server.")


# ── Clear ─────────────────────────────────────────────────────────────────────

class ClearModal(discord.ui.Modal, title="Clear Messages"):
    amount = discord.ui.TextInput(
        label="Number of messages to delete (1–100)",
        placeholder="10",
        required=True,
        max_length=3,
    )

    def __init__(self, channel: discord.TextChannel, moderator: discord.Member):
        super().__init__()
        self.channel = channel
        self.moderator = moderator

    async def on_submit(self, interaction: discord.Interaction):
        try:
            count = max(1, min(100, int(self.amount.value)))
        except ValueError:
            await interaction.response.send_message("❌ Please enter a valid number.", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True)
        deleted = await self.channel.purge(limit=count)
        embed = discord.Embed(
            title="🗑️ Messages Cleared",
            color=discord.Color.blurple(),
            timestamp=datetime.datetime.utcnow(),
        )
        embed.add_field(name="📢 Channel",     value=self.channel.mention,           inline=True)
        embed.add_field(name="🗑️ Deleted",    value=f"**{len(deleted)}** message(s)", inline=True)
        embed.add_field(name="🛡️ Moderator",  value=self.moderator.mention,          inline=True)
        embed.set_footer(text=datetime.datetime.utcnow().strftime("%d %b %Y • %H:%M UTC"))
        confirm = await self.channel.send(embed=embed)
        await confirm.delete(delay=5)


class ClearConfirmView(discord.ui.View):
    def __init__(self, channel: discord.TextChannel, moderator: discord.Member):
        super().__init__(timeout=60)
        self.channel = channel
        self.moderator = moderator

    @discord.ui.button(label="Choose Amount & Clear", style=discord.ButtonStyle.danger, emoji="🗑️")
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.moderator.id:
            await interaction.response.send_message("❌ Only the command invoker can do this.", ephemeral=True)
            return
        await interaction.response.send_modal(ClearModal(self.channel, self.moderator))
        self.stop()

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary, emoji="✖️")
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.moderator.id:
            await interaction.response.send_message("❌ Only the command invoker can do this.", ephemeral=True)
            return
        await interaction.response.edit_message(content="❌ Clear cancelled.", embed=None, view=None)
        self.stop()


@bot.command(name="clear")
@is_admin()
async def clear(ctx: commands.Context):
    """Clear messages with a popup.  Usage: ,clear"""
    embed = discord.Embed(
        title="🗑️ Clear Messages",
        description=f"You are about to delete messages in {ctx.channel.mention}.\nClick the button to choose how many.",
        color=discord.Color.blurple(),
    )
    embed.add_field(name="📢 Channel",    value=ctx.channel.mention,   inline=True)
    embed.add_field(name="🛡️ Moderator", value=ctx.author.mention,    inline=True)
    embed.set_footer(text="Max 100 messages at a time.")
    await ctx.send(embed=embed, view=ClearConfirmView(ctx.channel, ctx.author))


# ══════════════════════════════════════════════════════════════════════════════
# TIMEZONE — ,set timezone <city/country>  ·  ,timezone [@user]
# ══════════════════════════════════════════════════════════════════════════════

# Common short-hands and cities that aren't timezone names themselves
TZ_ALIASES = {
    # abbreviations
    "utc": "UTC", "gmt": "Etc/GMT", "ist": "Asia/Kolkata", "est": "America/New_York",
    "edt": "America/New_York", "cst": "America/Chicago", "cdt": "America/Chicago",
    "mst": "America/Denver", "mdt": "America/Denver", "pst": "America/Los_Angeles",
    "pdt": "America/Los_Angeles", "akst": "America/Anchorage", "hst": "Pacific/Honolulu",
    "bst": "Europe/London", "cet": "Europe/Paris", "cest": "Europe/Paris",
    "eet": "Europe/Athens", "msk": "Europe/Moscow", "pkt": "Asia/Karachi",
    "jst": "Asia/Tokyo", "kst": "Asia/Seoul", "sgt": "Asia/Singapore",
    "aest": "Australia/Sydney", "aedt": "Australia/Sydney", "awst": "Australia/Perth",
    "nzst": "Pacific/Auckland", "nzdt": "Pacific/Auckland",
    # India
    "india": "Asia/Kolkata", "hyderabad": "Asia/Kolkata", "mumbai": "Asia/Kolkata",
    "bombay": "Asia/Kolkata", "delhi": "Asia/Kolkata", "new delhi": "Asia/Kolkata",
    "bangalore": "Asia/Kolkata", "bengaluru": "Asia/Kolkata", "chennai": "Asia/Kolkata",
    "pune": "Asia/Kolkata", "ahmedabad": "Asia/Kolkata", "jaipur": "Asia/Kolkata",
    "lucknow": "Asia/Kolkata", "kochi": "Asia/Kolkata", "goa": "Asia/Kolkata",
    "noida": "Asia/Kolkata", "gurgaon": "Asia/Kolkata", "gurugram": "Asia/Kolkata",
    "vizag": "Asia/Kolkata", "visakhapatnam": "Asia/Kolkata", "vijayawada": "Asia/Kolkata",
    "warangal": "Asia/Kolkata", "chandigarh": "Asia/Kolkata", "indore": "Asia/Kolkata",
    # North America
    "usa": "America/New_York", "us": "America/New_York", "america": "America/New_York",
    "nyc": "America/New_York", "new york city": "America/New_York", "boston": "America/New_York",
    "miami": "America/New_York", "atlanta": "America/New_York", "philadelphia": "America/New_York",
    "washington dc": "America/New_York", "dc": "America/New_York", "orlando": "America/New_York",
    "houston": "America/Chicago", "dallas": "America/Chicago", "austin": "America/Chicago",
    "san antonio": "America/Chicago", "new orleans": "America/Chicago", "minneapolis": "America/Chicago",
    "la": "America/Los_Angeles", "san francisco": "America/Los_Angeles", "sf": "America/Los_Angeles",
    "seattle": "America/Los_Angeles", "las vegas": "America/Los_Angeles", "san diego": "America/Los_Angeles",
    "portland": "America/Los_Angeles", "california": "America/Los_Angeles", "texas": "America/Chicago",
    "florida": "America/New_York", "salt lake city": "America/Denver", "montreal": "America/Toronto",
    "ottawa": "America/Toronto", "calgary": "America/Edmonton",
    # Europe
    "uk": "Europe/London", "england": "Europe/London", "scotland": "Europe/London",
    "wales": "Europe/London", "manchester": "Europe/London", "birmingham": "Europe/London",
    "liverpool": "Europe/London", "glasgow": "Europe/London", "edinburgh": "Europe/London",
    "rotterdam": "Europe/Amsterdam", "the hague": "Europe/Amsterdam", "netherlands": "Europe/Amsterdam",
    "holland": "Europe/Amsterdam", "barcelona": "Europe/Madrid", "milan": "Europe/Rome",
    "munich": "Europe/Berlin", "frankfurt": "Europe/Berlin", "hamburg": "Europe/Berlin",
    "geneva": "Europe/Zurich", "lyon": "Europe/Paris", "marseille": "Europe/Paris",
    "krakow": "Europe/Warsaw", "st petersburg": "Europe/Moscow", "saint petersburg": "Europe/Moscow",
    # Middle East / Asia
    "uae": "Asia/Dubai", "abu dhabi": "Asia/Dubai", "sharjah": "Asia/Dubai",
    "doha": "Asia/Qatar", "jeddah": "Asia/Riyadh", "mecca": "Asia/Riyadh",
    "lahore": "Asia/Karachi", "islamabad": "Asia/Karachi", "beijing": "Asia/Shanghai",
    "china": "Asia/Shanghai", "shenzhen": "Asia/Shanghai", "guangzhou": "Asia/Shanghai",
    "osaka": "Asia/Tokyo", "kyoto": "Asia/Tokyo", "busan": "Asia/Seoul",
    "hanoi": "Asia/Bangkok", "phuket": "Asia/Bangkok", "bali": "Asia/Makassar",
    # Oceania / Africa / LatAm
    "canberra": "Australia/Sydney", "gold coast": "Australia/Brisbane", "wellington": "Pacific/Auckland",
    "cape town": "Africa/Johannesburg", "durban": "Africa/Johannesburg", "abuja": "Africa/Lagos",
    "rio": "America/Sao_Paulo", "rio de janeiro": "America/Sao_Paulo", "brasilia": "America/Sao_Paulo",
    "brazil": "America/Sao_Paulo",
    # big multi-timezone countries → their main city
    "australia": "Australia/Sydney", "canada": "America/Toronto", "russia": "Europe/Moscow",
    "mexico": "America/Mexico_City", "indonesia": "Asia/Jakarta", "germany": "Europe/Berlin",
    "spain": "Europe/Madrid", "portugal": "Europe/Lisbon", "argentina": "America/Argentina/Buenos_Aires",
    "chile": "America/Santiago", "new zealand": "Pacific/Auckland", "kazakhstan": "Asia/Almaty",
}

_TZ_BY_LOWER = {tz.lower(): tz for tz in pytz.all_timezones}
_TZ_BY_CITY: dict[str, str] = {}
for _tz in list(pytz.all_timezones) + list(pytz.common_timezones):   # common ones win
    _city = _tz.split("/")[-1].replace("_", " ").lower()
    _TZ_BY_CITY[_city] = _tz
_COUNTRY_BY_NAME = {name.lower(): code for code, name in pytz.country_names.items()}


def _offline_lookup(query: str) -> tuple[str, str | None] | None:
    """Return (tz_name, note) for a city / country / tz name, or None."""
    q = re.sub(r"\s+", " ", query.strip().lower())
    if not q:
        return None
    if q in _TZ_BY_LOWER:
        return _TZ_BY_LOWER[q], None
    if q in TZ_ALIASES:
        code = _COUNTRY_BY_NAME.get(q) or {"usa": "US", "us": "US", "america": "US"}.get(q)
        if code and len(pytz.country_timezones.get(code, [])) > 1:
            return TZ_ALIASES[q], (f"{pytz.country_names[code]} has several timezones — I used "
                                   f"`{TZ_ALIASES[q]}`. Set your city instead for an exact match.")
        return TZ_ALIASES[q], None
    if q in _TZ_BY_CITY:
        return _TZ_BY_CITY[q], None
    code = _COUNTRY_BY_NAME.get(q) or (q.upper() if len(q) == 2 and q.upper() in pytz.country_names else None)
    if code and code in pytz.country_timezones:
        zones = pytz.country_timezones[code]
        note = None
        if len(zones) > 1:
            note = (f"{pytz.country_names[code]} has {len(zones)} timezones — I used `{zones[0]}`. "
                    f"Set a city instead for an exact match.")
        return zones[0], note
    return None


def _online_lookup(query: str) -> str | None:
    """Optional fallback for any city on Earth (needs `pip install geopy timezonefinder`)."""
    try:
        from geopy.geocoders import Nominatim
        from timezonefinder import TimezoneFinder
    except ImportError:
        return None
    try:
        loc = Nominatim(user_agent="discord-tz-bot").geocode(query, timeout=10)
        if not loc:
            return None
        return TimezoneFinder().timezone_at(lng=loc.longitude, lat=loc.latitude)
    except Exception:
        return None


async def resolve_timezone(query: str) -> tuple[str, str | None] | None:
    found = _offline_lookup(query)
    if not found and "," in query:                       # "Hyderabad, India" → try each part
        for part in query.split(","):
            found = _offline_lookup(part)
            if found:
                break
    if found:
        return found
    tz = await asyncio.get_running_loop().run_in_executor(None, _online_lookup, query)
    return (tz, None) if tz else None


def timezone_embed(user: discord.abc.User, entry: dict) -> discord.Embed:
    tz = pytz.timezone(entry["tz"])
    now = datetime.datetime.now(tz)
    offset = now.strftime("%z")
    offset = f"UTC{offset[:3]}:{offset[3:]}"
    embed = discord.Embed(
        title=f"🕒 {user.display_name}'s Time",
        description=f"# {now.strftime('%I:%M %p').lstrip('0')}\n{now.strftime('%A, %d %B %Y')}",
        color=discord.Color.blurple(),
    )
    embed.set_thumbnail(url=user.display_avatar.url)
    embed.add_field(name="📍 Location", value=entry["place"], inline=True)
    embed.add_field(name="🌐 Timezone", value=f"`{entry['tz']}`", inline=True)
    embed.add_field(name="⏱️ Offset",   value=offset,          inline=True)
    return embed


@bot.group(name="set", invoke_without_command=True)
async def set_group(ctx: commands.Context):
    """Settings.  Usage: ,set timezone <city or country>"""
    await ctx.send(f"⚙️ Usage: `{PREFIX}set timezone <city or country>` — e.g. `{PREFIX}set timezone Hyderabad`")


@set_group.command(name="timezone", aliases=["tz"])
async def set_timezone(ctx: commands.Context, *, place: str):
    """Save your timezone.  Usage: ,set timezone <city or country>"""
    result = await resolve_timezone(place)
    if not result:
        await ctx.send(
            f"❌ I couldn't find **{place}**. Try a bigger nearby city, your country, "
            f"or a timezone name like `Asia/Kolkata`."
        )
        return
    tz_name, note = result
    entry = {"tz": tz_name, "place": place.strip().title()}
    data["timezones"][str(ctx.author.id)] = entry
    save_data()
    embed = timezone_embed(ctx.author, entry)
    embed.title = "✅ Timezone Saved"
    if note:
        embed.set_footer(text=note)
    await ctx.send(embed=embed)


@bot.group(name="timezone", aliases=["tz"], invoke_without_command=True)
async def timezone_cmd(ctx: commands.Context, member: discord.Member = None):
    """Check someone's local time.  Usage: ,timezone [@user]"""
    member = member or ctx.author
    entry = data["timezones"].get(str(member.id))
    if not entry:
        if member == ctx.author:
            await ctx.send(f"🌐 You haven't set a timezone yet. Use `{PREFIX}set timezone <city or country>`.")
        else:
            await ctx.send(f"🌐 **{member.display_name}** hasn't set their timezone yet.")
        return
    await ctx.send(embed=timezone_embed(member, entry))


@timezone_cmd.command(name="set")
async def timezone_set(ctx: commands.Context, *, place: str):
    """Shortcut: ,timezone set <city or country>"""
    await set_timezone(ctx, place=place)


@timezone_cmd.command(name="remove", aliases=["clear", "reset"])
async def timezone_remove(ctx: commands.Context):
    """Remove your saved timezone.  Usage: ,timezone remove"""
    if data["timezones"].pop(str(ctx.author.id), None):
        save_data()
        await ctx.send("🗑️ Your timezone has been removed.")
    else:
        await ctx.send("🌐 You don't have a timezone set.")


# ══════════════════════════════════════════════════════════════════════════════
# HARDBAN — a ban that cannot be lifted
# ══════════════════════════════════════════════════════════════════════════════

class HardbanConfirmView(discord.ui.View):
    def __init__(self, target: discord.abc.User, moderator: discord.Member, reason: str):
        super().__init__(timeout=60)
        self.target = target
        self.moderator = moderator
        self.reason = reason

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.moderator.id:
            await interaction.response.send_message("❌ Only the command invoker can do this.", ephemeral=True)
            return False
        return True

    @discord.ui.button(label="Hardban", style=discord.ButtonStyle.danger, emoji="⛔")
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        guild = interaction.guild
        try:
            await guild.ban(
                self.target,
                reason=f"[HARDBAN] {self.reason} (by {self.moderator})",
                delete_message_seconds=7 * 86400,
            )
        except discord.Forbidden:
            await interaction.response.edit_message(
                content="❌ I don't have permission to ban that user.", embed=None, view=None
            )
            return
        bans = data["hardbans"].setdefault(str(guild.id), [])
        if self.target.id not in bans:
            bans.append(self.target.id)
            save_data()
        embed = mod_result_embed(
            title="⛔ User Hardbanned",
            color=discord.Color.dark_red(),
            target=self.target,
            moderator=self.moderator,
            reason=self.reason,
            extra_fields=[
                ("🔒 Status", "Permanent — `,unban` and manual unbans are blocked", False),
                ("🗑️ Messages Deleted", "Last 7 days wiped", True),
            ],
        )
        await interaction.response.edit_message(embed=embed, view=None)
        self.stop()

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary, emoji="✖️")
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.edit_message(content="❌ Hardban cancelled.", embed=None, view=None)
        self.stop()


@bot.command(name="hardban")
@commands.guild_only()
@is_admin()
async def hardban(ctx: commands.Context, user: discord.User, *, reason: str = "No reason provided"):
    """Permanently ban a user — cannot be lifted.  Usage: ,hardban @user/ID [reason]"""
    member = ctx.guild.get_member(user.id)
    if member:
        err = hierarchy_error(ctx, member)
        if err:
            await ctx.send(err)
            return
    if user.id in data["hardbans"].get(str(ctx.guild.id), []):
        await ctx.send(f"⛔ **{user}** is already hardbanned.")
        return

    embed = discord.Embed(
        title="⛔ Hardban Confirmation",
        description="This ban **cannot be lifted**. Any unban — by command or manually — will be reverted instantly.",
        color=discord.Color.dark_red(),
    )
    embed.set_thumbnail(url=user.display_avatar.url)
    embed.add_field(name="👤 Target",  value=f"{user.mention} `{user}`", inline=True)
    embed.add_field(name="🪪 User ID", value=f"`{user.id}`",             inline=True)
    embed.add_field(name="📋 Reason",  value=reason,                     inline=False)
    embed.set_footer(text=f"Requested by {ctx.author.display_name}")
    await ctx.send(embed=embed, view=HardbanConfirmView(user, ctx.author, reason))


# ══════════════════════════════════════════════════════════════════════════════
# MUTE / UNMUTE — Discord timeouts
# ══════════════════════════════════════════════════════════════════════════════

MAX_TIMEOUT = datetime.timedelta(days=28)   # Discord's hard limit


@bot.command(name="mute", aliases=["timeout"])
@commands.guild_only()
@is_admin()
async def mute(ctx: commands.Context, member: discord.Member, *, args: str = ""):
    """Time out a member.  Usage: ,mute @user [duration e.g. 10m/2h/1d] [reason]"""
    err = hierarchy_error(ctx, member)
    if err:
        await ctx.send(err)
        return

    duration, reason = None, args
    if args:
        first, _, rest = args.partition(" ")
        parsed = parse_duration(first)
        if parsed:
            duration, reason = parsed, rest
    reason = reason.strip() or "No reason provided"

    note = None
    if duration is None:
        duration = MAX_TIMEOUT
        note = "No duration given — muted until `,unmute` (Discord max: 28 days)"
    elif duration > MAX_TIMEOUT:
        duration = MAX_TIMEOUT
        note = "Capped at 28 days (Discord's maximum)"

    try:
        await member.timeout(duration, reason=f"{reason} (by {ctx.author})")
    except discord.Forbidden:
        await ctx.send("❌ I can't mute that member. Check I have **Timeout Members** and my role is above theirs.")
        return

    ends = discord.utils.utcnow() + duration
    fields = [
        ("⏱️ Duration", format_duration(duration.total_seconds()), True),
        ("🔓 Ends",     discord.utils.format_dt(ends, "R"),        True),
    ]
    if note:
        fields.append(("ℹ️ Note", note, False))
    await ctx.send(embed=mod_result_embed(
        title="🔇 Member Muted", color=discord.Color.dark_grey(),
        target=member, moderator=ctx.author, reason=reason, extra_fields=fields,
    ))


@bot.command(name="unmute", aliases=["untimeout"])
@commands.guild_only()
@is_admin()
async def unmute(ctx: commands.Context, member: discord.Member, *, reason: str = "No reason provided"):
    """Remove a member's timeout.  Usage: ,unmute @user [reason]"""
    if not member.is_timed_out():
        await ctx.send(f"🔊 **{member.display_name}** isn't muted.")
        return
    try:
        await member.timeout(None, reason=f"{reason} (by {ctx.author})")
    except discord.Forbidden:
        await ctx.send("❌ I can't unmute that member. Check my permissions and role position.")
        return
    await ctx.send(embed=mod_result_embed(
        title="🔊 Member Unmuted", color=discord.Color.green(),
        target=member, moderator=ctx.author, reason=reason,
    ))


# ══════════════════════════════════════════════════════════════════════════════
# JAIL / UNJAIL — jailed members only see #jail
# ══════════════════════════════════════════════════════════════════════════════

async def setup_jail(guild: discord.Guild) -> tuple[discord.Role, discord.TextChannel]:
    """Make sure the Jailed role + #jail channel exist and every other channel is hidden from the role."""
    role = find_jail_role(guild)
    if role is None:
        role = await guild.create_role(
            name=JAIL_ROLE_NAME, permissions=discord.Permissions.none(),
            color=discord.Color.dark_grey(), reason="Jail system setup",
        )

    jail_overwrites = {
        guild.default_role: discord.PermissionOverwrite(view_channel=False),
        role: discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True),
        guild.me: discord.PermissionOverwrite(view_channel=True, send_messages=True, manage_channels=True),
    }
    channel = find_jail_channel(guild)
    if channel is None:
        channel = await guild.create_text_channel(
            JAIL_CHANNEL_NAME, overwrites=jail_overwrites, reason="Jail system setup",
            topic="You have been jailed. Wait here for a moderator.",
        )
    else:
        for target, ow in jail_overwrites.items():
            if channel.overwrites_for(target) != ow:
                await channel.set_permissions(target, overwrite=ow, reason="Jail system setup")

    # Hide every other channel/category from the jail role
    for ch in guild.channels:
        if ch.id == channel.id:
            continue
        ow = ch.overwrites_for(role)
        if ow.view_channel is not False:
            ow.view_channel = False
            try:
                await ch.set_permissions(role, overwrite=ow, reason="Hide from jailed members")
            except discord.HTTPException:
                pass
    return role, channel


async def apply_jail(guild: discord.Guild, member: discord.Member, reason: str, by: str) -> tuple[discord.TextChannel, int]:
    """Jail a member: give the jailed role, strip + save their other roles. Raises discord.Forbidden."""
    role, channel = await setup_jail(guild)
    gid = str(guild.id)
    me_top = guild.me.top_role
    removable = [r for r in member.roles if not r.is_default() and not r.managed and r < me_top and r != role]
    data["jailed"].setdefault(gid, {})[str(member.id)] = [r.id for r in removable]
    save_data()
    try:
        await member.add_roles(role, reason=f"Jailed: {reason} (by {by})")
        if removable:
            await member.remove_roles(*removable, reason=f"Jailed: {reason} (by {by})")
    except discord.Forbidden:
        data["jailed"][gid].pop(str(member.id), None)
        save_data()
        raise
    try:
        await channel.send(f"🔒 {member.mention}, you've been jailed.\n**Reason:** {reason}")
    except discord.HTTPException:
        pass
    return channel, len(removable)


@bot.command(name="jail")
@commands.guild_only()
@is_admin()
async def jail(ctx: commands.Context, member: discord.Member, *, reason: str = "No reason provided"):
    """Jail a member — they can only see #jail.  Usage: ,jail @user [reason]"""
    err = hierarchy_error(ctx, member)
    if err:
        await ctx.send(err)
        return
    gid = str(ctx.guild.id)
    if str(member.id) in data["jailed"].get(gid, {}):
        await ctx.send(f"🔒 **{member.display_name}** is already jailed.")
        return

    async with ctx.typing():
        try:
            channel, removed = await apply_jail(ctx.guild, member, reason, str(ctx.author))
        except discord.Forbidden:
            await ctx.send("❌ I couldn't jail them. I need **Manage Roles** + **Manage Channels**, "
                           "and my role must be above theirs.")
            return

    await ctx.send(embed=mod_result_embed(
        title="🔒 Member Jailed", color=discord.Color.dark_orange(),
        target=member, moderator=ctx.author, reason=reason,
        extra_fields=[
            ("📢 Channel",       channel.mention,                                   True),
            ("🎭 Roles Saved",   f"**{removed}** (restored on `,unjail`)",  True),
        ],
    ))


@bot.command(name="unjail")
@commands.guild_only()
@is_admin()
async def unjail(ctx: commands.Context, member: discord.Member, *, reason: str = "No reason provided"):
    """Release a member from jail and give back their roles.  Usage: ,unjail @user [reason]"""
    gid = str(ctx.guild.id)
    role = find_jail_role(ctx.guild)
    saved_ids = data["jailed"].get(gid, {}).get(str(member.id))
    if saved_ids is None and (role is None or role not in member.roles):
        await ctx.send(f"🔓 **{member.display_name}** isn't jailed.")
        return

    me_top = ctx.guild.me.top_role
    restore = [r for rid in (saved_ids or [])
               if (r := ctx.guild.get_role(rid)) and not r.managed and r < me_top]
    try:
        if restore:
            await member.add_roles(*restore, reason=f"Unjailed: {reason} (by {ctx.author})")
        if role and role in member.roles:
            await member.remove_roles(role, reason=f"Unjailed: {reason} (by {ctx.author})")
    except discord.Forbidden:
        await ctx.send("❌ I couldn't change that member's roles. Move my role above theirs.")
        return

    data["jailed"].get(gid, {}).pop(str(member.id), None)
    save_data()
    await ctx.send(embed=mod_result_embed(
        title="🔓 Member Unjailed", color=discord.Color.green(),
        target=member, moderator=ctx.author, reason=reason,
        extra_fields=[("🎭 Roles Restored", f"**{len(restore)}**", True)],
    ))


# ══════════════════════════════════════════════════════════════════════════════
# LOCKDOWN / UNLOCKDOWN — nobody can talk, invites paused, invite links blocked
# ══════════════════════════════════════════════════════════════════════════════

LOCK_PERMS = (
    "send_messages", "send_messages_in_threads", "create_public_threads",
    "create_private_threads", "add_reactions", "create_instant_invite", "connect",
)


async def apply_lockdown(guild: discord.Guild, reason: str, by: str) -> tuple[int, int, bool]:
    """Lock every channel for @everyone and pause invites. Returns (locked, failed, invites_paused)."""
    gid = str(guild.id)
    everyone = guild.default_role
    saved: dict[str, dict] = {}
    failed = 0
    # mark as locked immediately so invite-link blocking + anti-raid see it straight away
    data["lockdowns"][gid] = {"channels": saved, "invites_were_paused": "INVITES_DISABLED" in guild.features}

    for ch in guild.channels:
        if isinstance(ch, discord.CategoryChannel) or ch.name == JAIL_CHANNEL_NAME:
            continue
        ow = ch.overwrites_for(everyone)
        before = {p: getattr(ow, p) for p in LOCK_PERMS}
        ow.update(send_messages=False, send_messages_in_threads=False, create_public_threads=False,
                  create_private_threads=False, add_reactions=False, create_instant_invite=False)
        if isinstance(ch, (discord.VoiceChannel, discord.StageChannel)):
            ow.connect = False
        try:
            await ch.set_permissions(everyone, overwrite=ow, reason=f"Lockdown: {reason} (by {by})")
            saved[str(ch.id)] = before
        except discord.HTTPException:
            failed += 1

    invites_were_paused = data["lockdowns"][gid]["invites_were_paused"]
    invites_paused = invites_were_paused
    if not invites_were_paused:
        try:
            await guild.edit(invites_disabled=True, reason=f"Lockdown: {reason} (by {by})")
            invites_paused = True
        except (discord.HTTPException, TypeError):
            invites_paused = False

    save_data()
    return len(saved), failed, invites_paused


@bot.command(name="lockdown", aliases=["lock"])
@commands.guild_only()
@is_admin()
async def lockdown(ctx: commands.Context, *, reason: str = "No reason provided"):
    """Lock the whole server + pause invites.  Usage: ,lockdown [reason]"""
    guild = ctx.guild
    gid = str(guild.id)
    if gid in data["lockdowns"]:
        await ctx.send(f"🔒 The server is already locked down. Use `{PREFIX}unlockdown` to lift it.")
        return

    status = await ctx.send("🔒 Locking down the server…")
    locked, failed, invites_paused = await apply_lockdown(guild, reason, str(ctx.author))

    embed = discord.Embed(
        title="🔒 Server Locked Down",
        description="Members can't send messages, react, join voice, or create invites.",
        color=discord.Color.red(), timestamp=datetime.datetime.utcnow(),
    )
    embed.add_field(name="📢 Channels Locked", value=f"**{locked}**" + (f" ({failed} failed)" if failed else ""), inline=True)
    embed.add_field(name="✉️ Invites",         value="⏸️ Paused" if invites_paused else "⚠️ Couldn't pause", inline=True)
    embed.add_field(name="🔗 Invite Links",    value="Auto-deleted", inline=True)
    embed.add_field(name="🛡️ Moderator",      value=ctx.author.mention, inline=True)
    embed.add_field(name="📋 Reason",          value=reason, inline=False)
    embed.set_footer(text=f"Lift with {PREFIX}unlockdown")
    await status.edit(content=None, embed=embed)


@bot.command(name="unlockdown", aliases=["unlock"])
@commands.guild_only()
@is_admin()
async def unlockdown(ctx: commands.Context, *, reason: str = "No reason provided"):
    """Lift the lockdown and restore everything.  Usage: ,unlockdown [reason]"""
    guild = ctx.guild
    gid = str(guild.id)
    state = data["lockdowns"].get(gid)
    if not state:
        await ctx.send("🔓 The server isn't locked down.")
        return

    status = await ctx.send("🔓 Lifting lockdown…")
    everyone = guild.default_role
    restored = 0
    for ch_id, before in state["channels"].items():
        ch = guild.get_channel(int(ch_id))
        if ch is None:
            continue
        ow = ch.overwrites_for(everyone)
        ow.update(**before)
        try:
            await ch.set_permissions(everyone, overwrite=None if ow.is_empty() else ow,
                                     reason=f"Lockdown lifted: {reason} (by {ctx.author})")
            restored += 1
        except discord.HTTPException:
            pass

    invites_note = "Left paused (they were paused before lockdown)"
    if not state.get("invites_were_paused"):
        try:
            await guild.edit(invites_disabled=False, reason=f"Lockdown lifted (by {ctx.author})")
            invites_note = "▶️ Resumed"
        except (discord.HTTPException, TypeError):
            invites_note = "⚠️ Couldn't resume — do it in Server Settings → Invites"

    del data["lockdowns"][gid]
    save_data()

    embed = discord.Embed(title="🔓 Lockdown Lifted", color=discord.Color.green(),
                          timestamp=datetime.datetime.utcnow())
    embed.add_field(name="📢 Channels Restored", value=f"**{restored}**", inline=True)
    embed.add_field(name="✉️ Invites",           value=invites_note,      inline=True)
    embed.add_field(name="🛡️ Moderator",        value=ctx.author.mention, inline=True)
    embed.add_field(name="📋 Reason",            value=reason,            inline=False)
    await status.edit(content=None, embed=embed)


# ══════════════════════════════════════════════════════════════════════════════
# STRIP — remove every role from a member
# ══════════════════════════════════════════════════════════════════════════════

async def strip_roles(member: discord.Member, reason: str, by: str) -> tuple[list[discord.Role], list[discord.Role]]:
    """Remove every removable role. Returns (removed, kept). Raises discord.Forbidden."""
    me_top = member.guild.me.top_role
    roles = [r for r in member.roles if not r.is_default()]
    removable = [r for r in roles if not r.managed and r < me_top]
    kept = [r for r in roles if r not in removable]
    if removable:
        await member.remove_roles(*removable, reason=f"Stripped: {reason} (by {by})")
    return removable, kept


@bot.command(name="strip")
@commands.guild_only()
@is_admin()
async def strip(ctx: commands.Context, member: discord.Member, *, reason: str = "No reason provided"):
    """Take every role away from a member.  Usage: ,strip @user [reason]"""
    err = hierarchy_error(ctx, member)
    if err:
        await ctx.send(err)
        return

    try:
        removable, kept = await strip_roles(member, reason, str(ctx.author))
    except discord.Forbidden:
        await ctx.send("❌ I couldn't remove their roles. Move my role above theirs.")
        return
    if not removable:
        await ctx.send(f"🎭 **{member.display_name}** has no roles I can remove.")
        return

    def role_list(rs: list[discord.Role]) -> str:
        text = " ".join(r.mention for r in sorted(rs, reverse=True))
        return text if len(text) <= 1024 else text[:1000].rsplit(" ", 1)[0] + " …"

    fields = [(f"🗑️ Removed ({len(removable)})", role_list(removable), False)]
    if kept:
        fields.append((f"🔒 Couldn't remove ({len(kept)})",
                       role_list(kept) + "\n*Boost/bot roles, or above my role*", False))
    await ctx.send(embed=mod_result_embed(
        title="🎭 Roles Stripped", color=discord.Color.dark_purple(),
        target=member, moderator=ctx.author, reason=reason, extra_fields=fields,
    ))


# ══════════════════════════════════════════════════════════════════════════════
# HTTP session shared by ,topic and ,translate
# ══════════════════════════════════════════════════════════════════════════════

_http: aiohttp.ClientSession | None = None
HTTP_HEADERS = {"User-Agent": "DiscordBot/1.0 (discord.py; topic & translate commands)"}


async def http() -> aiohttp.ClientSession:
    global _http
    if _http is None or _http.closed:
        _http = aiohttp.ClientSession(headers=HTTP_HEADERS, timeout=aiohttp.ClientTimeout(total=15))
    return _http


def shorten(text: str, limit: int) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    return text if len(text) <= limit else text[: limit - 1].rsplit(" ", 1)[0] + "…"


# ══════════════════════════════════════════════════════════════════════════════
# TOPIC — Google-style search results
# ══════════════════════════════════════════════════════════════════════════════

def _web_search(query: str, limit: int) -> list[dict]:
    """Real web results via DuckDuckGo (pip install ddgs). Returns [] if unavailable."""
    try:
        from ddgs import DDGS
    except ImportError:
        return []
    try:
        return [
            {"title": r.get("title", ""), "url": r.get("href", ""), "snippet": r.get("body", "")}
            for r in DDGS().text(query, max_results=limit)
            if r.get("href")
        ]
    except Exception:
        return []


async def _wiki_search(query: str, limit: int) -> list[dict]:
    session = await http()
    params = {"action": "query", "list": "search", "srsearch": query,
              "srlimit": limit, "format": "json", "utf8": 1}
    async with session.get("https://en.wikipedia.org/w/api.php", params=params) as r:
        r.raise_for_status()
        payload = await r.json()
    results = []
    for hit in payload.get("query", {}).get("search", []):
        title = hit["title"]
        results.append({
            "title": title,
            "url": f"https://en.wikipedia.org/wiki/{quote(title.replace(' ', '_'))}",
            "snippet": html.unescape(re.sub(r"<[^>]+>", "", hit.get("snippet", ""))),
        })
    return results


async def _wiki_summary(title: str) -> dict | None:
    session = await http()
    url = f"https://en.wikipedia.org/api/rest_v1/page/summary/{quote(title.replace(' ', '_'), safe='')}"
    async with session.get(url) as r:
        if r.status != 200:
            return None
        payload = await r.json()
    if payload.get("type") == "disambiguation" or not payload.get("extract"):
        return None
    return {
        "title": payload.get("title", title),
        "extract": payload["extract"],
        "url": payload.get("content_urls", {}).get("desktop", {}).get("page"),
        "thumb": (payload.get("thumbnail") or {}).get("source"),
    }


@bot.command(name="topic", aliases=["search", "google"])
@commands.cooldown(1, 5, commands.BucketType.user)
async def topic(ctx: commands.Context, *, query: str):
    """Google-style results for a topic.  Usage: ,topic <anything>"""
    async with ctx.typing():
        loop = asyncio.get_running_loop()
        web_task = loop.run_in_executor(None, _web_search, query, 5)
        try:
            wiki_hits = await _wiki_search(query, 5)
        except Exception:
            wiki_hits = []
        summary = None
        if wiki_hits:
            try:
                summary = await _wiki_summary(wiki_hits[0]["title"])
            except Exception:
                summary = None
        results = await web_task or wiki_hits

    google_url = f"https://www.google.com/search?q={quote_plus(query)}"
    if not results and not summary:
        await ctx.send(f"🔎 No results found for **{query}**. Try [Google]({google_url}).")
        return

    embed = discord.Embed(title=f"🔎 {shorten(query, 200)}", url=google_url, color=0x4285F4)
    parts = []
    if summary:
        parts.append(f"### {summary['title']}\n{shorten(summary['extract'], 700)}")
        if summary["thumb"]:
            embed.set_thumbnail(url=summary["thumb"])
    for res in results[:5]:
        domain = urlparse(res["url"]).netloc.removeprefix("www.")
        parts.append(
            f"**[{shorten(res['title'], 90)}]({res['url']})**\n"
            f"-# 🌐 {domain}\n"
            f"{shorten(res['snippet'], 180)}"
        )
    embed.description = shorten_block("\n\n".join(parts), 4000)
    embed.set_footer(text=f"Requested by {ctx.author.display_name}",
                     icon_url=ctx.author.display_avatar.url)

    view = discord.ui.View()
    view.add_item(discord.ui.Button(label="Search on Google", url=google_url, emoji="🔎"))
    if summary and summary["url"]:
        view.add_item(discord.ui.Button(label="Wikipedia", url=summary["url"], emoji="📖"))
    await ctx.send(embed=embed, view=view)


def shorten_block(text: str, limit: int) -> str:
    """Trim multi-line text at a paragraph boundary."""
    if len(text) <= limit:
        return text
    return text[:limit].rsplit("\n\n", 1)[0]


# ══════════════════════════════════════════════════════════════════════════════
# TRANSLATE — reply to any message with ,translate → English
# ══════════════════════════════════════════════════════════════════════════════

LANGUAGE_NAMES = {
    "af": "Afrikaans", "sq": "Albanian", "am": "Amharic", "ar": "Arabic", "hy": "Armenian",
    "az": "Azerbaijani", "eu": "Basque", "be": "Belarusian", "bn": "Bengali", "bs": "Bosnian",
    "bg": "Bulgarian", "ca": "Catalan", "zh-CN": "Chinese (Simplified)", "zh-TW": "Chinese (Traditional)",
    "zh": "Chinese", "hr": "Croatian", "cs": "Czech", "da": "Danish", "nl": "Dutch", "en": "English",
    "eo": "Esperanto", "et": "Estonian", "tl": "Filipino", "fi": "Finnish", "fr": "French",
    "gl": "Galician", "ka": "Georgian", "de": "German", "el": "Greek", "gu": "Gujarati",
    "ht": "Haitian Creole", "ha": "Hausa", "iw": "Hebrew", "he": "Hebrew", "hi": "Hindi",
    "hu": "Hungarian", "is": "Icelandic", "ig": "Igbo", "id": "Indonesian", "ga": "Irish",
    "it": "Italian", "ja": "Japanese", "jw": "Javanese", "kn": "Kannada", "kk": "Kazakh",
    "km": "Khmer", "ko": "Korean", "ku": "Kurdish", "ky": "Kyrgyz", "lo": "Lao", "la": "Latin",
    "lv": "Latvian", "lt": "Lithuanian", "mk": "Macedonian", "ms": "Malay", "ml": "Malayalam",
    "mt": "Maltese", "mr": "Marathi", "mn": "Mongolian", "my": "Burmese", "ne": "Nepali",
    "no": "Norwegian", "or": "Odia", "ps": "Pashto", "fa": "Persian", "pl": "Polish",
    "pt": "Portuguese", "pa": "Punjabi", "ro": "Romanian", "ru": "Russian", "sr": "Serbian",
    "si": "Sinhala", "sk": "Slovak", "sl": "Slovenian", "so": "Somali", "es": "Spanish",
    "sw": "Swahili", "sv": "Swedish", "tg": "Tajik", "ta": "Tamil", "te": "Telugu", "th": "Thai",
    "tr": "Turkish", "uk": "Ukrainian", "ur": "Urdu", "uz": "Uzbek", "vi": "Vietnamese",
    "cy": "Welsh", "xh": "Xhosa", "yi": "Yiddish", "yo": "Yoruba", "zu": "Zulu",
}


async def translate_text(text: str, target: str = "en") -> tuple[str, str]:
    """Translate with Google Translate (auto-detects the source). Returns (translation, source_code)."""
    session = await http()
    pieces, source = [], "auto"
    # Google's free endpoint handles ~5000 chars per request; split on line breaks to be safe
    chunks, buf = [], ""
    for line in text.splitlines(keepends=True):
        if len(buf) + len(line) > 1800 and buf:
            chunks.append(buf)
            buf = ""
        buf += line
    chunks.append(buf)

    for chunk in chunks:
        params = {"client": "gtx", "sl": "auto", "tl": target, "dt": "t", "q": chunk}
        async with session.get("https://translate.googleapis.com/translate_a/single", params=params) as r:
            r.raise_for_status()
            payload = await r.json(content_type=None)
        pieces.append("".join(seg[0] for seg in payload[0] if seg and seg[0]))
        if source == "auto" and len(payload) > 2 and payload[2]:
            source = payload[2]
    return "".join(pieces), source


@bot.command(name="translate", aliases=["tr"])
@commands.cooldown(1, 3, commands.BucketType.user)
async def translate(ctx: commands.Context, *, text: str = None):
    """Translate to English. Reply to a message with ,translate  — or  ,translate <text>"""
    source_msg = None
    if ctx.message.reference and ctx.message.reference.message_id:
        ref = ctx.message.reference
        source_msg = ref.resolved if isinstance(ref.resolved, discord.Message) else None
        if source_msg is None:
            try:
                source_msg = await ctx.channel.fetch_message(ref.message_id)
            except discord.HTTPException:
                await ctx.send("❌ I couldn't find the message you replied to.")
                return
        text = source_msg.content
        if not text and source_msg.embeds:   # messages that are only an embed
            e = source_msg.embeds[0]
            text = "\n".join(filter(None, [e.title, e.description]))

    if not text or not text.strip():
        await ctx.send(f"🌐 Reply to a message with `{PREFIX}translate`, or use `{PREFIX}translate <text>`.")
        return

    async with ctx.typing():
        try:
            translated, src = await translate_text(text, "en")
        except Exception:
            await ctx.send("❌ Translation service didn't respond. Try again in a moment.")
            return

    src_name = LANGUAGE_NAMES.get(src) or LANGUAGE_NAMES.get(src.split("-")[0], src)
    author = source_msg.author if source_msg else ctx.author

    embed = discord.Embed(color=0x1A73E8)
    embed.set_author(name=author.display_name, icon_url=author.display_avatar.url)
    if src == "en":
        embed.title = "🌐 Already in English"
        embed.description = shorten_block(text, 4000)
    else:
        embed.title = f"🌐 {src_name} → English"
        embed.add_field(name=f"📝 Original ({src_name})", value=shorten(text, 1024), inline=False)
        embed.add_field(name="🇬🇧 English", value=translated[:1024], inline=False)
        if len(translated) > 1024:   # long messages: put the full translation in the description
            embed.clear_fields()
            embed.description = f"**🇬🇧 English**\n{translated[:4000]}"
    embed.set_footer(text=f"Requested by {ctx.author.display_name}")

    if source_msg:
        await source_msg.reply(embed=embed, mention_author=False)
    else:
        await ctx.reply(embed=embed, mention_author=False)


# ══════════════════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════════════════
# AUTHENTICATOR — Discord OAuth2 browser verification  (VaultCord-style)
#
# Flow:
#   1. Member joins → bot DMs a "Verify" button embed containing a unique
#      Discord OAuth2 URL with a per-member state token.
#   2. Member clicks → Discord consent screen → redirected to REDIRECT_URI
#      (the aiohttp web server running inside this process).
#   3. Web server exchanges the code for an access token, fetches the user's
#      Discord profile, validates the state token, grants the verified role,
#      and posts a completion embed to the log channel.
#   4. Browser shows a branded success (or error) HTML page.
# ══════════════════════════════════════════════════════════════════════════════

def _auth_log(event: str, user: discord.abc.User | None = None,
              guild: discord.Guild | None = None, **extra) -> None:
    """Write a structured auth event to the log file."""
    parts = [f"event={event}"]
    if user:
        parts.append(f"user={user} (id={user.id})")
    if guild:
        parts.append(f"guild={guild.name!r} (id={guild.id})")
    for k, v in extra.items():
        parts.append(f"{k}={v!r}")
    logger.info("[AUTH] " + " | ".join(parts))


async def _find_role(guild: discord.Guild, name: str) -> discord.Role | None:
    return discord.utils.find(lambda r: r.name.lower() == name.lower(), guild.roles)


def _build_oauth_url(state: str) -> str:
    params = (
        f"client_id={CLIENT_ID}"
        f"&redirect_uri={quote(REDIRECT_URI, safe='')}"
        f"&response_type=code"
        f"&scope=identify"
        f"&state={state}"
    )
    return f"{DISCORD_OAUTH_URL}?{params}"


async def start_auth(member: discord.Member) -> bool:
    """
    DM the member a branded verification button.
    Returns True if DM was sent, False if DMs are closed.
    """
    state = secrets.token_urlsafe(32)
    expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=OAUTH_STATE_EXPIRY)
    oauth_states[state] = {
        "guild_id": member.guild.id,
        "user_id":  member.id,
        "expires":  expires,
    }
    oauth_url = _build_oauth_url(state)
    _auth_log("oauth_link_issued", user=member, guild=member.guild,
              expires=expires.isoformat(timespec="seconds"))

    embed = discord.Embed(
        title=f"🔐 Verify your identity",
        description=(
            f"Welcome to **{member.guild.name}**!\n\n"
            f"Click the button below to verify yourself through Discord.\n"
            f"This link is **unique to you** and expires "
            f"<t:{int(expires.timestamp())}:R>."
        ),
        color=discord.Color.blurple(),
        timestamp=discord.utils.utcnow(),
    )
    embed.set_footer(text=f"{member.guild.name} • Powered by OAuth2 verification")
    view = discord.ui.View()
    view.add_item(discord.ui.Button(
        label="Verify with Discord",
        style=discord.ButtonStyle.link,
        url=oauth_url,
        emoji="🔗",
    ))
    try:
        await member.send(embed=embed, view=view)
        _auth_log("dm_sent", user=member, guild=member.guild)
        return True
    except discord.Forbidden:
        oauth_states.pop(state, None)
        _auth_log("dm_failed", user=member, guild=member.guild, reason="DMs closed")
        return False


async def complete_auth(member: discord.Member, discord_user: dict, ip: str | None = None) -> None:
    """
    Grant verified role, strip unverified role, persist, and post the
    detailed completion embed to the log channel.
    """
    guild  = member.guild
    now_ts = discord.utils.utcnow()

    # ── Role management ───────────────────────────────────────────────────────
    verified_role = await _find_role(guild, AUTH_VERIFY_ROLE)
    if verified_role:
        try:
            await member.add_roles(verified_role, reason="OAuth2 verification passed")
        except discord.HTTPException as exc:
            _auth_log("role_add_failed", user=member, guild=guild,
                      role=AUTH_VERIFY_ROLE, error=str(exc))
    if AUTH_UNVERIFIED_ROLE:
        unverified_role = await _find_role(guild, AUTH_UNVERIFIED_ROLE)
        if unverified_role and unverified_role in member.roles:
            try:
                await member.remove_roles(unverified_role, reason="OAuth2 verification passed")
            except discord.HTTPException as exc:
                _auth_log("role_remove_failed", user=member, guild=guild,
                          role=AUTH_UNVERIFIED_ROLE, error=str(exc))

    # ── Persist ───────────────────────────────────────────────────────────────
    gid = str(guild.id)
    data["verified"].setdefault(gid, {})[str(member.id)] = now_ts.isoformat(timespec="seconds")
    save_data()
    _auth_log("verified", user=member, guild=guild, ip=ip or "unknown")

    # ── Completion log embed (sent to the guild's log channel) ────────────────
    acct_age = format_duration(
        (now_ts - member.created_at).total_seconds()
    )
    join_age = format_duration(
        (now_ts - member.joined_at).total_seconds()
    ) if member.joined_at else "unknown"

    username_tag = f"{discord_user.get('username', '?')}#{discord_user.get('discriminator', '0')}" \
        if discord_user.get('discriminator', '0') != '0' \
        else discord_user.get('username', '?')

    e = discord.Embed(
        title="✅ Member Verified",
        color=discord.Color.green(),
        timestamp=now_ts,
    )
    avatar_url = (
        f"https://cdn.discordapp.com/avatars/{member.id}/{discord_user.get('avatar')}.png"
        if discord_user.get("avatar") else member.default_avatar.url
    )
    e.set_thumbnail(url=avatar_url)
    e.add_field(name="👤 User",        value=f"{member.mention}\n`{username_tag}`\nID: `{member.id}`", inline=True)
    e.add_field(name="🏠 Server",      value=f"{guild.name}\n`{guild.id}`",                           inline=True)
    e.add_field(name="🔑 Method",      value="Discord OAuth2 (browser)",                              inline=True)
    e.add_field(name="📆 Account Age", value=acct_age,                                                inline=True)
    e.add_field(name="⏱️ Time to Verify", value=join_age,                                            inline=True)
    e.add_field(name="🌐 IP Address",  value=f"`{ip}`" if ip else "`hidden`",                        inline=True)
    e.add_field(name="🎭 Role Granted", value=verified_role.mention if verified_role else f"`{AUTH_VERIFY_ROLE}` *(not found)*", inline=True)
    e.set_footer(text=f"Verified at")
    await send_log(guild, e)

    # ── DM the member a success message ──────────────────────────────────────
    success_embed = discord.Embed(
        title="✅ Verification Complete",
        description=f"You have been successfully verified in **{guild.name}**!\nYou now have access to the server. Welcome! 🎉",
        color=discord.Color.green(),
        timestamp=now_ts,
    )
    success_embed.set_footer(text=guild.name)
    try:
        await member.send(embed=success_embed)
    except discord.Forbidden:
        pass


# ── aiohttp web server (handles the OAuth2 redirect) ─────────────────────────

_HTML_SUCCESS = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verified ✅</title>
<style>
  *{{margin:0;padding:0;box-sizing:border-box}}
  body{{min-height:100vh;display:flex;align-items:center;justify-content:center;
       background:linear-gradient(135deg,#5865F2 0%,#404EED 100%);font-family:'gg sans','Noto Sans',sans-serif}}
  .card{{background:#fff;border-radius:16px;padding:48px 40px;max-width:420px;width:90%;
         text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.25)}}
  .icon{{font-size:56px;margin-bottom:16px}}
  h1{{color:#2c2f33;font-size:24px;font-weight:700;margin-bottom:10px}}
  p{{color:#5b6272;font-size:15px;line-height:1.5;margin-bottom:8px}}
  .tag{{display:inline-block;background:#f0f1ff;color:#5865F2;border-radius:8px;
        padding:6px 16px;font-weight:600;font-size:14px;margin-top:12px}}
  .close{{margin-top:28px;font-size:13px;color:#99aab5}}
</style>
</head>
<body>
  <div class="card">
    <div class="icon">✅</div>
    <h1>You're Verified!</h1>
    <p>You have been successfully verified in<br><strong>{guild_name}</strong>.</p>
    <div class="tag">@{role_name} role granted</div>
    <p class="close">You can close this tab and return to Discord.</p>
  </div>
</body>
</html>"""

_HTML_ERROR = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verification Failed</title>
<style>
  *{{margin:0;padding:0;box-sizing:border-box}}
  body{{min-height:100vh;display:flex;align-items:center;justify-content:center;
       background:linear-gradient(135deg,#ed4245 0%,#c0392b 100%);font-family:'gg sans','Noto Sans',sans-serif}}
  .card{{background:#fff;border-radius:16px;padding:48px 40px;max-width:420px;width:90%;
         text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.25)}}
  .icon{{font-size:56px;margin-bottom:16px}}
  h1{{color:#2c2f33;font-size:24px;font-weight:700;margin-bottom:10px}}
  p{{color:#5b6272;font-size:15px;line-height:1.5}}
  .code{{background:#fff0f0;color:#ed4245;border-radius:8px;padding:8px 16px;
         font-family:monospace;font-size:13px;margin-top:14px;display:inline-block}}
</style>
</head>
<body>
  <div class="card">
    <div class="icon">❌</div>
    <h1>Verification Failed</h1>
    <p>{message}</p>
    <div class="code">{code}</div>
  </div>
</body>
</html>"""


async def _oauth_callback(request: web.Request) -> web.Response:
    """Handle GET /auth — the Discord OAuth2 redirect endpoint."""
    code  = request.rel_url.query.get("code")
    state = request.rel_url.query.get("state")
    error = request.rel_url.query.get("error")
    ip    = request.headers.get("X-Forwarded-For", request.remote).split(",")[0].strip()

    def err(msg: str, code_str: str = "") -> web.Response:
        return web.Response(
            content_type="text/html",
            text=_HTML_ERROR.format(message=msg, code=code_str),
        )

    if error:
        _auth_log("oauth_denied", state=state, error=error, ip=ip)
        return err("You denied the verification request.", f"error={error}")

    if not code or not state:
        return err("Missing OAuth2 parameters.", "code or state missing")

    entry = oauth_states.pop(state, None)
    if entry is None:
        _auth_log("oauth_invalid_state", state=state[:16], ip=ip)
        return err("This verification link is invalid or has already been used.", "invalid_state")

    now = datetime.datetime.now(datetime.timezone.utc)
    if now > entry["expires"]:
        _auth_log("oauth_expired_state", ip=ip)
        return err("This verification link has expired. Please rejoin or ask an admin to resend.", "link_expired")

    guild_id = entry["guild_id"]
    user_id  = entry["user_id"]

    # ── Exchange code for access token ────────────────────────────────────────
    async with aiohttp.ClientSession() as session:
        resp = await session.post(
            DISCORD_TOKEN_URL,
            data={
                "client_id":     CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "grant_type":    "authorization_code",
                "code":          code,
                "redirect_uri":  REDIRECT_URI,
            },
        )
        if resp.status != 200:
            _auth_log("oauth_token_exchange_failed", status=resp.status, ip=ip)
            return err("Failed to exchange OAuth2 code. Please try again.", f"http_{resp.status}")
        token_data = await resp.json()

    access_token = token_data.get("access_token")
    if not access_token:
        return err("No access token received.", "no_token")

    # ── Fetch Discord user info ───────────────────────────────────────────────
    async with aiohttp.ClientSession() as session:
        resp = await session.get(
            DISCORD_ME_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if resp.status != 200:
            return err("Could not fetch your Discord profile.", f"http_{resp.status}")
        discord_user = await resp.json()

    authed_id = int(discord_user.get("id", 0))
    if authed_id != user_id:
        _auth_log("oauth_id_mismatch", expected=user_id, got=authed_id, ip=ip)
        return err(
            "The Discord account you authorised doesn't match the account that joined the server. "
            "Please use the correct account.",
            "id_mismatch",
        )

    # ── Apply roles via bot ───────────────────────────────────────────────────
    guild = bot.get_guild(guild_id)
    if guild is None:
        return err("Bot is no longer in that server.", "guild_missing")

    member = guild.get_member(user_id)
    if member is None:
        try:
            member = await guild.fetch_member(user_id)
        except discord.NotFound:
            return err("You've left the server.", "member_left")

    already = data["verified"].get(str(guild_id), {}).get(str(user_id))
    if already:
        _auth_log("oauth_already_verified", user=member, guild=guild, ip=ip)
        return web.Response(
            content_type="text/html",
            text=_HTML_SUCCESS.format(guild_name=guild.name, role_name=AUTH_VERIFY_ROLE),
        )

    await complete_auth(member, discord_user, ip=ip)

    return web.Response(
        content_type="text/html",
        text=_HTML_SUCCESS.format(guild_name=guild.name, role_name=AUTH_VERIFY_ROLE),
    )


async def _health(request: web.Request) -> web.Response:
    """GET / — health check used by Render's uptime monitor and our self-ping."""
    return web.Response(text="OK")


async def _keep_alive() -> None:
    """
    Render free plan spins down after ~15 min of no inbound HTTP traffic.
    This task pings our own /health endpoint every 10 minutes so the web
    server (and therefore the OAuth callback) stays awake.
    The RENDER_EXTERNAL_URL env var is set automatically by Render.
    """
    base = os.environ.get("RENDER_EXTERNAL_URL", "").rstrip("/")
    if not base:
        logger.info("[WEB] RENDER_EXTERNAL_URL not set — self-ping disabled (local mode)")
        return
    url = f"{base}/"
    await asyncio.sleep(60)          # wait for server to fully start first
    while True:
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(url, timeout=aiohttp.ClientTimeout(total=15)) as r:
                    logger.info(f"[KEEPALIVE] ping {url} → {r.status}")
        except Exception as exc:
            logger.warning(f"[KEEPALIVE] ping failed: {exc}")
        await asyncio.sleep(600)     # ping every 10 minutes


async def start_web_server() -> None:
    """Start the aiohttp web server that handles OAuth2 redirects."""
    app = web.Application()
    app.router.add_get("/",     _health)           # health / keep-alive endpoint
    app.router.add_get("/auth", _oauth_callback)   # Discord OAuth2 redirect
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, OAUTH_HOST, OAUTH_PORT)
    await site.start()
    logger.info(f"[WEB] OAuth2 callback server listening on {OAUTH_HOST}:{OAUTH_PORT}")
    asyncio.get_event_loop().create_task(_keep_alive())


# ── Auth admin commands ────────────────────────────────────────────────────────

@bot.group(name="auth", invoke_without_command=True)
@commands.guild_only()
@is_admin()
async def auth_group(ctx: commands.Context):
    """Auth management.  Sub-commands: status · resend · revoke · list"""
    await ctx.send("📋 Sub-commands: `status` · `resend` · `revoke` · `list`\n"
                   "Example: `,auth resend @user`")


@auth_group.command(name="status")
@commands.guild_only()
@is_admin()
async def auth_status(ctx: commands.Context, member: discord.Member):
    """Check a member's verification status.  Usage: ,auth status @user"""
    gid = str(ctx.guild.id)
    uid = str(member.id)
    verified_at = data["verified"].get(gid, {}).get(uid)
    pending_state = next(
        (s for s, v in oauth_states.items() if v.get("user_id") == member.id), None
    )
    e = discord.Embed(title=f"🔐 Auth Status — {member.display_name}", color=discord.Color.blurple())
    e.set_thumbnail(url=member.display_avatar.url)
    if verified_at:
        ts = int(datetime.datetime.fromisoformat(verified_at).timestamp())
        e.add_field(name="✅ Verified", value=f"<t:{ts}:F>", inline=False)
    else:
        e.add_field(name="❌ Not verified", value="Has not completed browser verification", inline=False)
    if pending_state:
        exp = oauth_states[pending_state]["expires"]
        e.add_field(name="⏳ Pending OAuth link",
                    value=f"Expires <t:{int(exp.timestamp())}:R>", inline=False)
    await ctx.send(embed=e)
    _auth_log("admin_status_check", user=member, guild=ctx.guild, checked_by=str(ctx.author))


@auth_group.command(name="resend")
@commands.guild_only()
@is_admin()
async def auth_resend(ctx: commands.Context, member: discord.Member):
    """Resend a verification link to a member.  Usage: ,auth resend @user"""
    # Invalidate any existing pending state for this user
    for st in [s for s, v in oauth_states.items() if v.get("user_id") == member.id]:
        oauth_states.pop(st, None)
    sent = await start_auth(member)
    if sent:
        await ctx.send(f"📨 New verification link sent to **{member.display_name}** via DM.")
        _auth_log("admin_resend", user=member, guild=ctx.guild, by=str(ctx.author))
    else:
        await ctx.send(f"❌ Could not DM **{member.display_name}** — their DMs may be closed.")


@auth_group.command(name="revoke")
@commands.guild_only()
@is_admin()
async def auth_revoke(ctx: commands.Context, member: discord.Member, *, reason: str = "No reason provided"):
    """Revoke a member's verified status.  Usage: ,auth revoke @user [reason]"""
    gid, uid = str(ctx.guild.id), str(member.id)
    was_verified = data["verified"].get(gid, {}).pop(uid, None)
    for st in [s for s, v in oauth_states.items() if v.get("user_id") == member.id]:
        oauth_states.pop(st, None)
    save_data()

    verified_role   = await _find_role(ctx.guild, AUTH_VERIFY_ROLE)
    unverified_role = await _find_role(ctx.guild, AUTH_UNVERIFIED_ROLE) if AUTH_UNVERIFIED_ROLE else None
    if verified_role and verified_role in member.roles:
        try:
            await member.remove_roles(verified_role, reason=f"Auth revoked: {reason}")
        except discord.HTTPException:
            pass
    if unverified_role and unverified_role not in member.roles:
        try:
            await member.add_roles(unverified_role, reason=f"Auth revoked: {reason}")
        except discord.HTTPException:
            pass

    _auth_log("admin_revoke", user=member, guild=ctx.guild,
              was_verified=bool(was_verified), reason=reason, by=str(ctx.author))
    e = discord.Embed(
        title="🔓 Verification Revoked",
        color=discord.Color.red(),
        description=f"**{member.display_name}**'s verified status has been revoked."
    )
    e.add_field(name="📝 Reason", value=reason)
    e.add_field(name="🛡️ By", value=ctx.author.mention)
    await ctx.send(embed=e)
    await send_log(ctx.guild, e)
    try:
        await member.send(
            f"🔓 Your verified status in **{ctx.guild.name}** was revoked.\n"
            f"Reason: {reason}\n\nAsk an admin to resend a new verification link."
        )
    except discord.Forbidden:
        pass


@auth_group.command(name="list")
@commands.guild_only()
@is_admin()
async def auth_list(ctx: commands.Context):
    """List all verified members in this server.  Usage: ,auth list"""
    gid = str(ctx.guild.id)
    verified = data["verified"].get(gid, {})
    e = discord.Embed(
        title=f"✅ Verified Members — {ctx.guild.name}",
        color=discord.Color.green(),
        description=f"**{len(verified)}** verified member(s)"
    )
    lines = []
    for uid, ts in list(verified.items())[-20:]:
        t = int(datetime.datetime.fromisoformat(ts).timestamp())
        lines.append(f"<@{uid}> — <t:{t}:d>")
    if lines:
        e.add_field(name="Members (latest 20)", value="\n".join(lines), inline=False)
    else:
        e.description = "No verified members yet."
    await ctx.send(embed=e)
    _auth_log("admin_list", guild=ctx.guild, by=str(ctx.author), count=len(verified))


# SECURITY — anti-raid · anti-spam · anti-ping · anti-link · anti-nuke · warns · logs
# All numbers live in security_config.py  (edit, then ,security reload)
# ══════════════════════════════════════════════════════════════════════════════

PUNISHMENTS = {"warn", "mute", "kick", "jail", "strip", "ban"}

spam_tracker: dict[tuple[int, int], deque] = defaultdict(deque)   # (guild, user) -> (time, message)
dup_tracker:  dict[tuple[int, int], tuple[str, int]] = {}         # (guild, user) -> (last text, repeats)
join_tracker: dict[int, deque] = defaultdict(deque)                # guild -> join times
nuke_tracker: dict[tuple[int, int, str], deque] = defaultdict(deque)
raid_in_progress: set[int] = set()
automod_deleted: set[int] = set()        # message ids the bot deleted itself (not logged / not ghost pings)

CUSTOM_EMOJI_RE  = re.compile(r"<a?:\w+:\d+>")
UNICODE_EMOJI_RE = re.compile("[\U0001F300-\U0001FAFF\U00002600-\U000027BF\U0001F1E6-\U0001F1FF]")
URL_RE           = re.compile(r"https?://([^\s/<>]+)", re.IGNORECASE)
ALWAYS_OK_HOSTS  = {"discord.com", "discordapp.com", "cdn.discordapp.com", "media.discordapp.net"}


def security_ids() -> set[int]:
    return {int(i) for i in sc.SECURITY_USER_IDS}


def is_security_user(guild: discord.Guild, user: discord.abc.User) -> bool:
    ids = security_ids()
    return user.id in ids if ids else user.id == guild.owner_id


def security_only():
    async def predicate(ctx: commands.Context) -> bool:
        if ctx.guild is None:
            raise commands.NoPrivateMessage()
        if is_security_user(ctx.guild, ctx.author):
            return True
        raise commands.CheckFailure("🔐 Only security managers can use that command.")
    return commands.check(predicate)


def sec(guild: discord.Guild) -> dict:
    """Per-server security state (on/off switches, log channel, whitelist, extra allowed domains)."""
    s = data["security"].setdefault(str(guild.id), {})
    for key, default in sc.DEFAULT_ENABLED.items():
        s.setdefault(key, default)
    s.setdefault("log_channel", None)
    s.setdefault("whitelist", [])
    s.setdefault("link_allow", [])
    return s


def is_immune(member: discord.abc.User) -> bool:
    """Admins, whitelisted users, security managers and bots are never auto-punished."""
    if not isinstance(member, discord.Member):
        return True
    g = member.guild
    if member.bot or member.id == g.owner_id or member.guild_permissions.administrator:
        return True
    if member.id in security_ids() or member.id in sec(g)["whitelist"]:
        return True
    wanted = {_norm(n) for n in ADMIN_ROLE_NAMES}
    return any(_norm(r.name) in wanted for r in member.roles)


def who(user) -> str:
    if user is None:
        return "Unknown"
    if hasattr(user, "mention"):
        return f"{user.mention} `{user}`"
    return f"`{getattr(user, 'id', user)}`"


def log_embed(title: str, color: discord.Color, description: str | None = None) -> discord.Embed:
    return discord.Embed(title=title, description=description, color=color,
                         timestamp=discord.utils.utcnow())


async def send_log(guild: discord.Guild, embed: discord.Embed) -> None:
    cid = sec(guild).get("log_channel")
    channel = guild.get_channel(cid) if cid else None
    if channel:
        try:
            await channel.send(embed=embed)
        except discord.HTTPException:
            pass


async def alert_security(guild: discord.Guild, embed: discord.Embed) -> None:
    """Post in the log channel AND DM every security manager (or the owner)."""
    await send_log(guild, embed)
    for uid in (security_ids() or {guild.owner_id}):
        user = bot.get_user(uid)
        try:
            user = user or await bot.fetch_user(uid)
            dm = embed.copy()
            dm.set_footer(text=f"Server: {guild.name}")
            await user.send(embed=dm)
        except discord.HTTPException:
            pass


# ── Warnings ──────────────────────────────────────────────────────────────────

async def add_warning(guild: discord.Guild, member: discord.Member, reason: str,
                      moderator: discord.abc.User) -> tuple[int, str | None]:
    """Store a warning. Returns (total warnings, automatic action taken or None)."""
    warns = data["warnings"].setdefault(str(guild.id), {}).setdefault(str(member.id), [])
    warns.append({"reason": reason, "mod": moderator.id, "ts": discord.utils.utcnow().timestamp()})
    save_data()
    count = len(warns)
    escalation = None
    step = sc.WARN_ACTIONS.get(count)
    if step:
        action, minutes = step
        if action in PUNISHMENTS and action != "warn":
            escalation = await punish(member, action, f"Reached {count} warnings", minutes, give_warn=False)
    return count, escalation


async def punish(member: discord.Member, action: str, reason: str, minutes: int = 0,
                 give_warn: bool | None = None) -> str:
    """Apply an automatic punishment. Returns a short description of what happened."""
    guild = member.guild
    by = "Auto-mod"
    if give_warn is None:
        give_warn = sc.AUTOMOD_GIVES_WARN and action != "warn"
    try:
        if action == "warn":
            count, esc = await add_warning(guild, member, reason, guild.me)
            result = f"warned (now {count} warning{'s' if count != 1 else ''})" + (f" → {esc}" if esc else "")
            give_warn = False
        elif action == "mute":
            minutes = minutes or 10
            await member.timeout(min(datetime.timedelta(minutes=minutes), MAX_TIMEOUT), reason=f"{reason} ({by})")
            result = f"muted for {format_duration(minutes * 60)}"
        elif action == "kick":
            await member.kick(reason=f"{reason} ({by})")
            result = "kicked"
        elif action == "ban":
            await member.ban(reason=f"{reason} ({by})", delete_message_seconds=86400)
            result = "banned"
        elif action == "jail":
            if str(member.id) in data["jailed"].get(str(guild.id), {}):
                result = "already jailed"
            else:
                await apply_jail(guild, member, reason, by)
                result = "jailed"
        elif action == "strip":
            removed, _ = await strip_roles(member, reason, by)
            result = f"stripped of {len(removed)} role(s)"
        else:
            return f"no action (unknown punishment `{action}` in security_config.py)"
    except discord.HTTPException:
        return f"couldn't be {action}ed — my role is too low or I'm missing permissions"

    if give_warn and action not in ("kick", "ban"):
        count, esc = await add_warning(guild, member, reason, guild.me)
        result += f" + warned ({count})" + (f" → {esc}" if esc else "")
    return result


# ── Auto-mod (runs on every message) ─────────────────────────────────────────

def count_emojis(text: str) -> int:
    return len(CUSTOM_EMOJI_RE.findall(text)) + len(UNICODE_EMOJI_RE.findall(CUSTOM_EMOJI_RE.sub("", text)))


def blocked_link(content: str, guild: discord.Guild) -> str | None:
    """Return what's blocked ('invite' or the domain), or None."""
    if INVITE_RE.search(content):
        return "invite"
    if sc.BLOCK_ALL_LINKS:
        allowed = {d.lower().removeprefix("www.") for d in sc.ALLOWED_DOMAINS} | set(sec(guild)["link_allow"]) | ALWAYS_OK_HOSTS
        for host in URL_RE.findall(content):
            host = host.lower().split(":")[0].removeprefix("www.")
            if not any(host == d or host.endswith("." + d) for d in allowed):
                return host
    return None


async def automod_delete(message: discord.Message, notice: str | None) -> None:
    automod_deleted.add(message.id)
    try:
        await message.delete()
    except discord.HTTPException:
        pass
    if notice:
        try:
            await message.channel.send(f"{message.author.mention} {notice}", delete_after=6)
        except discord.HTTPException:
            pass


async def log_automod(message: discord.Message, what: str, action: str | None = None) -> None:
    e = log_embed(f"🤖 Auto-mod: {what}", discord.Color.orange())
    e.add_field(name="👤 User", value=who(message.author), inline=True)
    e.add_field(name="📢 Channel", value=message.channel.mention, inline=True)
    if action:
        e.add_field(name="⚖️ Action", value=action, inline=True)
    if message.content:
        e.add_field(name="💬 Message", value=shorten(message.content, 1000), inline=False)
    await send_log(message.guild, e)


async def run_automod(message: discord.Message) -> bool:
    """Returns True if the message was removed (stop processing it)."""
    if not message.guild or not isinstance(message.author, discord.Member) or is_immune(message.author):
        return False
    s = sec(message.guild)
    member, content = message.author, message.content or ""
    key = (message.guild.id, member.id)

    # ── Anti-link
    if s["antilink"]:
        hit = blocked_link(content, message.guild)
        if hit:
            await automod_delete(message, "🔗 invite links aren't allowed here." if hit == "invite"
                                 else "🔗 that link isn't allowed here.")
            await log_automod(message, "Blocked link" if hit != "invite" else "Blocked invite")
            return True

    # ── Anti-ping
    if s["antiping"]:
        if sc.BLOCK_EVERYONE_PING and ("@everyone" in content or "@here" in content):
            await automod_delete(message, "📢 you can't ping everyone.")
            await log_automod(message, "@everyone / @here attempt")
            return True
        pinged = {u.id for u in message.mentions if not u.bot and u.id != member.id}
        total = len(pinged) + len(message.role_mentions)
        if sc.PING_LIMIT and total >= sc.PING_LIMIT:
            await automod_delete(message, None)
            result = await punish(member, sc.PING_PUNISHMENT, f"Mass ping ({total} mentions)", sc.PING_MUTE_MINUTES)
            await message.channel.send(f"🚨 {member.mention} was **{result}** for mass pinging.", delete_after=10)
            await log_automod(message, f"Mass ping ({total} mentions)", result)
            return True

    if s["antispam"]:
        # ── Message flood
        now = asyncio.get_running_loop().time()
        dq = spam_tracker[key]
        dq.append((now, message))
        while dq and now - dq[0][0] > sc.SPAM_SECONDS:
            dq.popleft()
        if sc.SPAM_MESSAGE_COUNT and len(dq) >= sc.SPAM_MESSAGE_COUNT:
            msgs = [m for _, m in dq]
            dq.clear()
            by_channel: dict[int, list[discord.Message]] = defaultdict(list)
            for m in msgs:
                automod_deleted.add(m.id)
                by_channel[m.channel.id].append(m)
            for ch_msgs in by_channel.values():
                try:
                    await ch_msgs[0].channel.delete_messages(ch_msgs)
                except discord.HTTPException:
                    pass
            result = await punish(member, sc.SPAM_PUNISHMENT, "Message spam", sc.SPAM_MUTE_MINUTES)
            await message.channel.send(f"🚨 {member.mention} was **{result}** for spamming.", delete_after=10)
            await log_automod(message, f"Spam ({len(msgs)} messages in {sc.SPAM_SECONDS}s)", result)
            return True

        # ── Repeated message
        if sc.DUPLICATE_LIMIT and content.strip():
            text = content.strip().lower()
            last, n = dup_tracker.get(key, (None, 0))
            n = n + 1 if text == last else 1
            dup_tracker[key] = (text, n)
            if n >= sc.DUPLICATE_LIMIT:
                await automod_delete(message, "🔁 stop repeating the same message.")
                await log_automod(message, f"Repeated message ({n}x)")
                return True

        # ── Content filters
        reason = None
        letters = [c for c in content if c.isalpha()]
        if sc.MAX_MESSAGE_LENGTH and len(content) > sc.MAX_MESSAGE_LENGTH:
            reason = "wall of text"
        elif sc.MAX_LINES and content.count("\n") + 1 > sc.MAX_LINES:
            reason = "too many lines"
        elif sc.MAX_EMOJIS and count_emojis(content) > sc.MAX_EMOJIS:
            reason = "emoji spam"
        elif (sc.CAPS_PERCENT and len(content) >= sc.CAPS_MIN_LENGTH and letters
              and sum(c.isupper() for c in letters) / len(letters) * 100 >= sc.CAPS_PERCENT):
            reason = "caps spam"
        if reason:
            await automod_delete(message, f"⚠️ your message was removed ({reason}).")
            await log_automod(message, reason.capitalize())
            return True

    return False


# ── Anti-raid / account age (called from on_member_join) ─────────────────────

async def security_on_join(member: discord.Member) -> bool:
    """Returns True if the member was removed."""
    guild, s = member.guild, sec(member.guild)

    if s["minage"] and not member.bot:
        age = discord.utils.utcnow() - member.created_at
        if age < datetime.timedelta(days=sc.MIN_ACCOUNT_AGE_DAYS):
            try:
                await member.send(f"👋 Your account is too new to join **{guild.name}** "
                                  f"(must be at least {sc.MIN_ACCOUNT_AGE_DAYS} days old). Try again later!")
            except discord.HTTPException:
                pass
            try:
                await member.kick(reason=f"Account younger than {sc.MIN_ACCOUNT_AGE_DAYS} days")
                e = log_embed("👶 New Account Kicked", discord.Color.orange())
                e.add_field(name="👤 User", value=who(member), inline=True)
                e.add_field(name="📆 Account Age", value=format_duration(age.total_seconds()), inline=True)
                await send_log(guild, e)
                return True
            except discord.HTTPException:
                pass

    if s["antiraid"]:
        now = asyncio.get_running_loop().time()
        dq = join_tracker[guild.id]
        dq.append(now)
        while dq and now - dq[0] > sc.RAID_JOIN_SECONDS:
            dq.popleft()
        if (len(dq) >= sc.RAID_JOIN_COUNT and guild.id not in raid_in_progress
                and str(guild.id) not in data["lockdowns"]):
            raid_in_progress.add(guild.id)
            joins = len(dq)
            dq.clear()
            try:
                reason = f"Anti-raid: {joins} joins in {sc.RAID_JOIN_SECONDS}s"
                locked, failed, paused = await apply_lockdown(guild, reason, "Anti-raid")
                e = log_embed("🚨 RAID DETECTED — Server Locked Down", discord.Color.red(),
                              f"**{joins}** accounts joined within **{sc.RAID_JOIN_SECONDS}s**.")
                e.add_field(name="📢 Channels Locked", value=str(locked), inline=True)
                e.add_field(name="✉️ Invites", value="⏸️ Paused" if paused else "⚠️ Couldn't pause", inline=True)
                e.add_field(name="🧹 Next Steps",
                            value=f"`{PREFIX}raidban {sc.RAIDBAN_DEFAULT_MINUTES}m` to ban the raiders\n"
                                  f"`{PREFIX}unlockdown` when it's over", inline=False)
                await alert_security(guild, e)
            finally:
                raid_in_progress.discard(guild.id)
    return False


# ── Anti-nuke + audit logging ────────────────────────────────────────────────

NUKE_ACTIONS = {
    discord.AuditLogAction.ban:            "ban",
    discord.AuditLogAction.kick:           "kick",
    discord.AuditLogAction.channel_delete: "channel_delete",
    discord.AuditLogAction.channel_create: "channel_create",
    discord.AuditLogAction.role_delete:    "role_delete",
    discord.AuditLogAction.role_create:    "role_create",
    discord.AuditLogAction.webhook_create: "webhook_create",
}


async def handle_nuker(guild: discord.Guild, user_id: int, action: str, count: int, seconds: int) -> None:
    member = guild.get_member(user_id)
    if member is None:
        try:
            member = await guild.fetch_member(user_id)
        except discord.HTTPException:
            return
    punishment = "ban" if member.bot else sc.NUKE_PUNISHMENT
    reason = f"Anti-nuke: {count}x {action.replace('_', ' ')} in {seconds}s"
    try:
        if punishment == "ban":
            await member.ban(reason=reason)
            result = "🔨 Banned"
        elif punishment == "kick":
            await member.kick(reason=reason)
            result = "👢 Kicked"
        else:
            removed, _ = await strip_roles(member, reason, "Anti-nuke")
            result = f"🎭 Stripped of {len(removed)} role(s)"
    except discord.HTTPException:
        result = "⚠️ **Couldn't punish them** — their role is above mine. Act manually NOW."

    e = log_embed("☢️ ANTI-NUKE TRIGGERED", discord.Color.dark_red(),
                  f"{who(member)} did **{count}× {action.replace('_', ' ')}** within **{seconds}s**.")
    e.add_field(name="⚖️ Action", value=result, inline=False)
    e.add_field(name="💡 False alarm?", value=f"`{PREFIX}whitelist add @user` so it ignores them.", inline=False)
    await alert_security(guild, e)


async def log_audit_entry(entry: discord.AuditLogEntry) -> None:
    A, guild = discord.AuditLogAction, entry.guild
    target, mod = entry.target, entry.user
    if entry.action == A.ban:
        e = log_embed("🔨 Member Banned", discord.Color.red())
    elif entry.action == A.unban:
        e = log_embed("✅ Member Unbanned", discord.Color.green())
    elif entry.action == A.kick:
        e = log_embed("👢 Member Kicked", discord.Color.orange())
    elif entry.action == A.member_update:
        before_t = getattr(entry.before, "timed_out_until", None)
        after_t = getattr(entry.after, "timed_out_until", None)
        if after_t and after_t != before_t:
            e = log_embed("🔇 Member Muted", discord.Color.dark_grey())
            e.add_field(name="🔓 Ends", value=discord.utils.format_dt(after_t, "R"), inline=True)
        elif before_t and not after_t:
            e = log_embed("🔊 Member Unmuted", discord.Color.green())
        else:
            return
    elif entry.action == A.member_role_update:
        added = getattr(entry.after, "roles", None) or []
        removed = getattr(entry.before, "roles", None) or []
        e = log_embed("🎭 Roles Changed", discord.Color.blurple())
        if added:
            e.add_field(name="➕ Added", value=shorten(" ".join(getattr(r, "mention", str(r)) for r in added), 1000), inline=False)
        if removed:
            e.add_field(name="➖ Removed", value=shorten(" ".join(getattr(r, "mention", str(r)) for r in removed), 1000), inline=False)
    elif entry.action == A.channel_delete:
        e = log_embed("🗑️ Channel Deleted", discord.Color.red(),
                      f"`#{getattr(entry.before, 'name', 'unknown')}`")
        e.add_field(name="🛡️ By", value=who(mod), inline=True)
        await send_log(guild, e)
        return
    elif entry.action == A.role_delete:
        e = log_embed("🗑️ Role Deleted", discord.Color.red(), f"`@{getattr(entry.before, 'name', 'unknown')}`")
        e.add_field(name="🛡️ By", value=who(mod), inline=True)
        await send_log(guild, e)
        return
    else:
        return
    e.add_field(name="👤 User", value=who(target), inline=True)
    e.add_field(name="🛡️ By", value=who(mod), inline=True)
    if entry.reason:
        e.add_field(name="📋 Reason", value=shorten(entry.reason, 1000), inline=False)
    await send_log(guild, e)


@bot.event
async def on_audit_log_entry_create(entry: discord.AuditLogEntry):
    guild = entry.guild
    await log_audit_entry(entry)

    key = NUKE_ACTIONS.get(entry.action)
    if not key or not sec(guild)["antinuke"] or key not in sc.NUKE_LIMITS:
        return
    uid = entry.user_id
    if uid is None or uid == bot.user.id or uid == guild.owner_id:
        return
    if uid in security_ids() or uid in sec(guild)["whitelist"]:
        return
    count, seconds = sc.NUKE_LIMITS[key]
    now = asyncio.get_running_loop().time()
    dq = nuke_tracker[(guild.id, uid, key)]
    dq.append(now)
    while dq and now - dq[0] > seconds:
        dq.popleft()
    if len(dq) >= count:
        dq.clear()
        await handle_nuker(guild, uid, key, count, seconds)


# ── Message / member logging + ghost pings ───────────────────────────────────

@bot.event
async def on_message_delete(message: discord.Message):
    if message.id in automod_deleted:
        automod_deleted.discard(message.id)
        return
    if not message.guild or message.author.bot:
        return
    s = sec(message.guild)

    # Ghost ping: pinged someone, then deleted it quickly
    if s["antiping"] and sc.GHOST_PING_SECONDS and not (message.content or "").startswith(PREFIX):
        pinged = [u for u in message.mentions if not u.bot and u.id != message.author.id]
        age = (discord.utils.utcnow() - message.created_at).total_seconds()
        if (pinged or message.role_mentions) and age <= sc.GHOST_PING_SECONDS:
            e = discord.Embed(title="👻 Ghost Ping Detected", color=discord.Color.light_grey(),
                              description=shorten(message.content, 1500) or "*(no text)*")
            e.set_author(name=message.author.display_name, icon_url=message.author.display_avatar.url)
            e.add_field(name="🎯 Pinged",
                        value=" ".join([u.mention for u in pinged] + [r.mention for r in message.role_mentions])[:1024],
                        inline=False)
            try:
                await message.channel.send(embed=e)
            except discord.HTTPException:
                pass

    e = log_embed("🗑️ Message Deleted", discord.Color.red())
    e.add_field(name="👤 Author", value=who(message.author), inline=True)
    e.add_field(name="📢 Channel", value=message.channel.mention, inline=True)
    if message.content:
        e.add_field(name="💬 Content", value=shorten(message.content, 1000), inline=False)
    if message.attachments:
        e.add_field(name="📎 Attachments", value="\n".join(a.filename for a in message.attachments)[:1000], inline=False)
    await send_log(message.guild, e)


@bot.event
async def on_message_edit(before: discord.Message, after: discord.Message):
    if not before.guild or before.author.bot or before.content == after.content:
        return
    e = log_embed("✏️ Message Edited", discord.Color.gold())
    e.add_field(name="👤 Author", value=who(before.author), inline=True)
    e.add_field(name="📢 Channel", value=f"{before.channel.mention} • [Jump]({after.jump_url})", inline=True)
    e.add_field(name="Before", value=shorten(before.content, 1000) or "*(empty)*", inline=False)
    e.add_field(name="After",  value=shorten(after.content, 1000) or "*(empty)*", inline=False)
    await send_log(before.guild, e)


@bot.event
async def on_member_remove(member: discord.Member):
    e = log_embed("📤 Member Left", discord.Color.dark_grey())
    e.set_thumbnail(url=member.display_avatar.url)
    e.add_field(name="👤 User", value=who(member), inline=True)
    if member.joined_at:
        e.add_field(name="⏱️ Was Here For",
                    value=format_duration((discord.utils.utcnow() - member.joined_at).total_seconds()), inline=True)
    await send_log(member.guild, e)


# ── Security commands (security managers only) ───────────────────────────────

def make_toggle(name: str, label: str, description: str):
    @bot.command(name=name, help=f"{description}  Usage: ,{name} on/off")
    @commands.guild_only()
    @security_only()
    async def _toggle(ctx: commands.Context, state: str = None):
        s = sec(ctx.guild)
        if state is None:
            await ctx.send(f"{label} is **{'ON ✅' if s[name] else 'OFF ❌'}**. Use `{PREFIX}{name} on` / `{PREFIX}{name} off`.")
            return
        state = state.lower()
        if state not in ("on", "off", "enable", "disable", "true", "false"):
            await ctx.send(f"⚠️ Usage: `{PREFIX}{name} on` or `{PREFIX}{name} off`")
            return
        s[name] = state in ("on", "enable", "true")
        save_data()
        await ctx.send(f"{label} is now **{'ON ✅' if s[name] else 'OFF ❌'}**.")
    return _toggle


make_toggle("antiraid", "🚨 Anti-raid",   "Auto-lockdown when lots of accounts join at once.")
make_toggle("antispam", "💬 Anti-spam",   "Message flood, repeats, walls of text, emoji & caps spam.")
make_toggle("antiping", "📢 Anti-ping",   "Mass pings, @everyone attempts and ghost pings.")
make_toggle("antinuke", "☢️ Anti-nuke",   "Punish anyone mass-banning/kicking or deleting channels/roles.")
make_toggle("minage",   "👶 Min account age", "Kick brand-new accounts when they join.")


@bot.group(name="antilink", invoke_without_command=True)
@commands.guild_only()
@security_only()
async def antilink(ctx: commands.Context, state: str = None):
    """Block invite links (and optionally all links).  Usage: ,antilink on/off | allow/remove/list"""
    s = sec(ctx.guild)
    if state is None:
        mode = "all links except allowed" if sc.BLOCK_ALL_LINKS else "Discord invites only"
        await ctx.send(f"🔗 Anti-link is **{'ON ✅' if s['antilink'] else 'OFF ❌'}** — blocking {mode}.\n"
                       f"`{PREFIX}antilink on/off` • `{PREFIX}antilink allow <domain>` • `{PREFIX}antilink list`")
        return
    if state.lower() not in ("on", "off"):
        await ctx.send(f"⚠️ Usage: `{PREFIX}antilink on` / `off` / `allow <domain>` / `remove <domain>` / `list`")
        return
    s["antilink"] = state.lower() == "on"
    save_data()
    await ctx.send(f"🔗 Anti-link is now **{'ON ✅' if s['antilink'] else 'OFF ❌'}**.")


@antilink.command(name="allow", aliases=["add"])
async def antilink_allow(ctx: commands.Context, domain: str):
    domain = domain.lower().removeprefix("https://").removeprefix("http://").removeprefix("www.").split("/")[0]
    s = sec(ctx.guild)
    if domain not in s["link_allow"]:
        s["link_allow"].append(domain)
        save_data()
    await ctx.send(f"✅ `{domain}` links are allowed.")


@antilink.command(name="remove", aliases=["del"])
async def antilink_remove(ctx: commands.Context, domain: str):
    domain = domain.lower().removeprefix("www.")
    s = sec(ctx.guild)
    if domain in s["link_allow"]:
        s["link_allow"].remove(domain)
        save_data()
        await ctx.send(f"🗑️ `{domain}` removed from the allow-list.")
    elif domain in [d.lower() for d in sc.ALLOWED_DOMAINS]:
        await ctx.send(f"⚠️ `{domain}` is in **security_config.py** — remove it there, then `{PREFIX}security reload`.")
    else:
        await ctx.send(f"❓ `{domain}` isn't on the allow-list.")


@antilink.command(name="list")
async def antilink_list(ctx: commands.Context):
    extra = sec(ctx.guild)["link_allow"]
    e = discord.Embed(title="🔗 Allowed Domains", color=discord.Color.blurple())
    e.add_field(name="From security_config.py", value=", ".join(f"`{d}`" for d in sc.ALLOWED_DOMAINS) or "None", inline=False)
    e.add_field(name="Added with ,antilink allow", value=", ".join(f"`{d}`" for d in extra) or "None", inline=False)
    e.set_footer(text="Only matters when BLOCK_ALL_LINKS = True. Invites are always blocked.")
    await ctx.send(embed=e)


# antilink subcommands inherit the group's checks
for _cmd in (antilink_allow, antilink_remove, antilink_list):
    _cmd.add_check(lambda ctx: is_security_user(ctx.guild, ctx.author) if ctx.guild else False)


@bot.group(name="whitelist", invoke_without_command=True)
@commands.guild_only()
@security_only()
async def whitelist(ctx: commands.Context):
    """People auto-mod & anti-nuke ignore.  Usage: ,whitelist add/remove @user | ,whitelist list"""
    await whitelist_list(ctx)


@whitelist.command(name="add")
async def whitelist_add(ctx: commands.Context, user: discord.User):
    wl = sec(ctx.guild)["whitelist"]
    if user.id not in wl:
        wl.append(user.id)
        save_data()
    await ctx.send(f"✅ **{user}** is whitelisted — auto-mod and anti-nuke will ignore them.")


@whitelist.command(name="remove", aliases=["del"])
async def whitelist_remove(ctx: commands.Context, user: discord.User):
    wl = sec(ctx.guild)["whitelist"]
    if user.id in wl:
        wl.remove(user.id)
        save_data()
        await ctx.send(f"🗑️ **{user}** removed from the whitelist.")
    else:
        await ctx.send(f"❓ **{user}** isn't whitelisted.")


@whitelist.command(name="list")
async def whitelist_list(ctx: commands.Context):
    wl = sec(ctx.guild)["whitelist"]
    text = "\n".join(f"<@{uid}> `{uid}`" for uid in wl) or "Nobody yet."
    e = discord.Embed(title="🛡️ Whitelist", description=text, color=discord.Color.blurple())
    e.set_footer(text="Admins & security managers are always immune to auto-mod. Anti-nuke only ignores "
                      "the owner, security managers and this list.")
    await ctx.send(embed=e)


for _cmd in (whitelist_add, whitelist_remove, whitelist_list):
    _cmd.add_check(lambda ctx: is_security_user(ctx.guild, ctx.author) if ctx.guild else False)


@bot.command(name="setlog")
@commands.guild_only()
@security_only()
async def setlog(ctx: commands.Context, channel: discord.TextChannel = None):
    """Set the log channel.  Usage: ,setlog #channel  |  ,setlog (turns logging off)"""
    s = sec(ctx.guild)
    s["log_channel"] = channel.id if channel else None
    save_data()
    if channel:
        await ctx.send(f"📝 Logs will go to {channel.mention}.")
        await send_log(ctx.guild, log_embed("📝 Logging Enabled", discord.Color.green(),
                                            f"Set by {ctx.author.mention}"))
    else:
        await ctx.send("📝 Logging turned **off**.")


class RaidbanConfirmView(discord.ui.View):
    def __init__(self, targets: list[discord.Member], moderator: discord.Member):
        super().__init__(timeout=60)
        self.targets = targets
        self.moderator = moderator

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.moderator.id:
            await interaction.response.send_message("❌ Only the command invoker can do this.", ephemeral=True)
            return False
        return True

    @discord.ui.button(label="Ban them all", style=discord.ButtonStyle.danger, emoji="🔨")
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.edit_message(content=f"🔨 Banning {len(self.targets)} accounts…", embed=None, view=None)
        banned = 0
        for m in self.targets:
            try:
                await m.ban(reason=f"Raid ban (by {self.moderator})", delete_message_seconds=86400)
                banned += 1
            except discord.HTTPException:
                pass
        e = log_embed("🔨 Raid Ban Complete", discord.Color.red(),
                      f"Banned **{banned}/{len(self.targets)}** accounts.")
        e.add_field(name="🛡️ By", value=self.moderator.mention, inline=True)
        await interaction.edit_original_response(content=None, embed=e)
        await send_log(interaction.guild, e)
        self.stop()

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary, emoji="✖️")
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.edit_message(content="❌ Raid ban cancelled.", embed=None, view=None)
        self.stop()


@bot.command(name="raidban")
@commands.guild_only()
@security_only()
async def raidban(ctx: commands.Context, window: str = None):
    """Ban everyone who joined recently.  Usage: ,raidban [5m / 1h]"""
    span = parse_duration(window) if window else datetime.timedelta(minutes=sc.RAIDBAN_DEFAULT_MINUTES)
    if span is None:
        await ctx.send(f"⚠️ Usage: `{PREFIX}raidban 5m` (or 30s, 1h…)")
        return
    cutoff = discord.utils.utcnow() - span
    targets = [m for m in ctx.guild.members
               if m.joined_at and m.joined_at >= cutoff and not m.bot and not is_immune(m)]
    if not targets:
        await ctx.send(f"✅ Nobody (non-admin) joined in the last **{format_duration(span.total_seconds())}**.")
        return
    preview = "\n".join(f"• {m.mention} `{m}`" for m in targets[:20])
    if len(targets) > 20:
        preview += f"\n…and **{len(targets) - 20}** more"
    e = discord.Embed(title=f"🔨 Raid Ban — {len(targets)} account(s)", color=discord.Color.red(),
                      description=f"Everyone who joined in the last **{format_duration(span.total_seconds())}**:\n\n{preview}")
    await ctx.send(embed=e, view=RaidbanConfirmView(targets, ctx.author))


@bot.group(name="security", aliases=["sec"], invoke_without_command=True)
@commands.guild_only()
@security_only()
async def security(ctx: commands.Context):
    """Security overview panel.  Usage: ,security  |  ,security reload"""
    s = sec(ctx.guild)
    on = lambda k: "✅" if s[k] else "❌"
    log_ch = ctx.guild.get_channel(s["log_channel"]) if s["log_channel"] else None
    e = discord.Embed(title="🛡️ Security Panel", color=discord.Color.blurple())
    e.add_field(name=f"{on('antiraid')} Anti-raid",
                value=f"{sc.RAID_JOIN_COUNT} joins / {sc.RAID_JOIN_SECONDS}s → lockdown", inline=True)
    e.add_field(name=f"{on('minage')} Min account age",
                value=f"{sc.MIN_ACCOUNT_AGE_DAYS} days", inline=True)
    e.add_field(name=f"{on('antispam')} Anti-spam",
                value=f"{sc.SPAM_MESSAGE_COUNT} msgs / {sc.SPAM_SECONDS}s → {sc.SPAM_PUNISHMENT}"
                      + (f" {sc.SPAM_MUTE_MINUTES}m" if sc.SPAM_PUNISHMENT == "mute" else ""), inline=True)
    e.add_field(name=f"{on('antiping')} Anti-ping",
                value=f"{sc.PING_LIMIT}+ pings → {sc.PING_PUNISHMENT}"
                      + (f" {sc.PING_MUTE_MINUTES}m" if sc.PING_PUNISHMENT == "mute" else "")
                      + f"\nGhost pings: {'on' if sc.GHOST_PING_SECONDS else 'off'}", inline=True)
    e.add_field(name=f"{on('antilink')} Anti-link",
                value="All links except allowed" if sc.BLOCK_ALL_LINKS else "Invites only", inline=True)
    e.add_field(name=f"{on('antinuke')} Anti-nuke",
                value=f"→ {sc.NUKE_PUNISHMENT}", inline=True)
    e.add_field(name="⚠️ Warn Steps",
                value=", ".join(f"{n} → {a}" + (f" {m}m" if a == "mute" else "")
                                for n, (a, m) in sorted(sc.WARN_ACTIONS.items())) or "None", inline=True)
    e.add_field(name="📝 Log Channel", value=log_ch.mention if log_ch else "Not set (`,setlog #channel`)", inline=True)
    e.add_field(name="🛡️ Whitelisted", value=f"{len(s['whitelist'])} user(s)", inline=True)
    ids = security_ids()
    e.add_field(name="🔐 Security Managers",
                value=" ".join(f"<@{i}>" for i in ids) if ids else "Server owner only (list in security_config.py is empty)",
                inline=False)
    e.set_footer(text="Numbers live in security_config.py • ,security reload after editing")
    await ctx.send(embed=e)


@security.command(name="reload")
async def security_reload(ctx: commands.Context):
    """Reload security_config.py without restarting."""
    try:
        path = Path(sc.__file__).with_suffix(".py")
        fresh: dict = {}
        exec(compile(path.read_text(encoding="utf-8"), str(path), "exec"), fresh)   # always read the real file
        for k, v in fresh.items():
            if k.isupper():
                setattr(sc, k, v)
    except Exception as err:
        await ctx.send(f"❌ security_config.py has an error, kept the old settings:\n```{err}```")
        return
    bad = [f"{n}={getattr(sc, n)!r}" for n in ("SPAM_PUNISHMENT", "PING_PUNISHMENT")
           if getattr(sc, n) not in PUNISHMENTS]
    if sc.NUKE_PUNISHMENT not in ("strip", "kick", "ban"):
        bad.append(f"NUKE_PUNISHMENT={sc.NUKE_PUNISHMENT!r}")
    msg = "✅ Reloaded **security_config.py**."
    if bad:
        msg += "\n⚠️ Unknown punishment(s): " + ", ".join(bad) + " — use warn / mute / kick / jail / strip / ban."
    await ctx.send(msg)

security_reload.add_check(lambda ctx: is_security_user(ctx.guild, ctx.author) if ctx.guild else False)


# ── Warnings (admin commands) ────────────────────────────────────────────────

@bot.command(name="warn")
@commands.guild_only()
@is_admin()
async def warn(ctx: commands.Context, member: discord.Member, *, reason: str = "No reason provided"):
    """Warn a member.  Usage: ,warn @user [reason]"""
    err = hierarchy_error(ctx, member)
    if err:
        await ctx.send(err)
        return
    count, escalation = await add_warning(ctx.guild, member, reason, ctx.author)
    fields = [("⚠️ Total Warnings", f"**{count}**", True)]
    if escalation:
        fields.append(("⚖️ Automatic Action", escalation, True))
    else:
        nxt = min((n for n in sc.WARN_ACTIONS if n > count), default=None)
        if nxt:
            fields.append(("⏭️ Next Step", f"{nxt} warnings → {sc.WARN_ACTIONS[nxt][0]}", True))
    embed = mod_result_embed(title="⚠️ Member Warned", color=discord.Color.gold(),
                             target=member, moderator=ctx.author, reason=reason, extra_fields=fields)
    await ctx.send(embed=embed)
    await send_log(ctx.guild, embed)
    try:
        await member.send(f"⚠️ You were warned in **{ctx.guild.name}**: {reason}\n(You now have {count} warning(s).)")
    except discord.HTTPException:
        pass


@bot.command(name="warnings", aliases=["warns"])
@commands.guild_only()
@is_admin()
async def warnings(ctx: commands.Context, member: discord.Member):
    """List a member's warnings.  Usage: ,warnings @user"""
    warns = data["warnings"].get(str(ctx.guild.id), {}).get(str(member.id), [])
    e = discord.Embed(title=f"⚠️ {member.display_name}'s Warnings — {len(warns)}", color=discord.Color.gold())
    e.set_thumbnail(url=member.display_avatar.url)
    if not warns:
        e.description = "No warnings. 😇"
    for i, w in enumerate(warns[-20:], start=max(1, len(warns) - 19)):
        when = discord.utils.format_dt(datetime.datetime.fromtimestamp(w["ts"], datetime.timezone.utc), "R")
        mod = "Auto-mod" if w["mod"] == bot.user.id else f"<@{w['mod']}>"
        e.add_field(name=f"#{i}", value=f"{shorten(w['reason'], 200)}\n-# by {mod} • {when}", inline=False)
    await ctx.send(embed=e)


@bot.command(name="clearwarns", aliases=["clearwarnings"])
@commands.guild_only()
@is_admin()
async def clearwarns(ctx: commands.Context, member: discord.Member):
    """Remove all of a member's warnings.  Usage: ,clearwarns @user"""
    removed = data["warnings"].get(str(ctx.guild.id), {}).pop(str(member.id), [])
    save_data()
    await ctx.send(f"🧹 Cleared **{len(removed)}** warning(s) from **{member.display_name}**.")


# ── Entry point (Render-compatible) ───────────────────────────────────────────
# bot.run() blocks and manages its own event loop, but we need the aiohttp web
# server running in the same loop. We use bot.start() (a coroutine) instead and
# drive both with asyncio.run().

async def _main() -> None:
    for var in ("DISCORD_TOKEN", "DISCORD_CLIENT_ID", "DISCORD_CLIENT_SECRET", "REDIRECT_URI"):
        if not os.environ.get(var):
            raise EnvironmentError(
                f"Required environment variable {var!r} is not set. "
                f"Add it in Render → your service → Environment."
            )
    await start_web_server()
    await bot.start(TOKEN)


if __name__ == "__main__":
    asyncio.run(_main())
