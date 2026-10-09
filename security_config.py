# ══════════════════════════════════════════════════════════════════════════════
#  SECURITY SETTINGS
#  Change any number here, save, then type  ,security reload  in Discord
#  (no restart needed).
# ══════════════════════════════════════════════════════════════════════════════

# ── Who can use the security commands ─────────────────────────────────────────
# Discord → Settings → Advanced → turn on Developer Mode.
# Then right-click a user → Copy User ID, and paste it below (no quotes).
# If this list is EMPTY, only the server owner can use them.
SECURITY_USER_IDS = [
    # 123456789012345678,   # me
    # 987654321098765432,   # someone else who gets it
]


# ── Which protections start ON in a new server ────────────────────────────────
# (After that, turn them on/off with the commands, e.g.  ,antispam off)
DEFAULT_ENABLED = {
    "antiraid": True,
    "antispam": True,
    "antiping": True,
    "antilink": False,
    "antinuke": True,
    "minage":   False,
}


# ── Anti-raid ─────────────────────────────────────────────────────────────────
RAID_JOIN_COUNT   = 10     # this many joins…
RAID_JOIN_SECONDS = 10     # …within this many seconds = raid → automatic lockdown

MIN_ACCOUNT_AGE_DAYS = 7   # ,minage on → accounts younger than this get kicked on join

RAIDBAN_DEFAULT_MINUTES = 5   # ,raidban with no time bans everyone who joined in the last X minutes


# ── Anti-spam ─────────────────────────────────────────────────────────────────
SPAM_MESSAGE_COUNT = 6     # this many messages…
SPAM_SECONDS       = 5     # …within this many seconds = spam
SPAM_PUNISHMENT    = "mute"    # warn / mute / kick / jail / strip / ban
SPAM_MUTE_MINUTES  = 10        # only used when the punishment is "mute"

DUPLICATE_LIMIT    = 3     # same message this many times in a row → deleted   (0 = off)
MAX_MESSAGE_LENGTH = 1500  # longer messages are deleted (wall of text)       (0 = off)
MAX_LINES          = 25    # messages with more lines are deleted             (0 = off)
MAX_EMOJIS         = 10    # messages with more emojis are deleted            (0 = off)
CAPS_PERCENT       = 70    # % capital letters that counts as caps spam       (0 = off)
CAPS_MIN_LENGTH    = 15    # caps check only applies to messages at least this long


# ── Anti-ping ─────────────────────────────────────────────────────────────────
PING_LIMIT         = 5         # mentioning this many users/roles in one message = mass ping
PING_PUNISHMENT    = "mute"    # warn / mute / kick / jail / strip / ban
PING_MUTE_MINUTES  = 30

BLOCK_EVERYONE_PING = True     # delete @everyone / @here attempts from non-admins
GHOST_PING_SECONDS  = 60       # ping deleted within this many seconds = ghost ping reported (0 = off)


# ── Anti-link ─────────────────────────────────────────────────────────────────
# Discord invites to other servers are ALWAYS blocked when ,antilink is on.
BLOCK_ALL_LINKS = False        # True = also block every other link except the domains below
ALLOWED_DOMAINS = [            # always allowed (more can be added with ,antilink allow <domain>)
    "youtube.com", "youtu.be", "tenor.com", "giphy.com", "spotify.com",
    "twitch.tv", "imgur.com",
]


# ── Anti-nuke ─────────────────────────────────────────────────────────────────
# If ONE person does an action too many times too fast, they get punished.
#   action:            (how many, within how many seconds)
NUKE_LIMITS = {
    "ban":             (3, 30),
    "kick":            (3, 30),
    "channel_delete":  (2, 30),
    "channel_create":  (5, 30),
    "role_delete":     (2, 30),
    "role_create":     (5, 30),
    "webhook_create":  (3, 60),
}
NUKE_PUNISHMENT = "strip"      # strip / kick / ban   (bots that nuke are always banned)


# ── Warnings ──────────────────────────────────────────────────────────────────
# When someone reaches this many warnings → this happens automatically.
#   warnings: (punishment, minutes — only used for "mute")
WARN_ACTIONS = {
    3: ("mute", 60),
    5: ("jail", 0),
}
AUTOMOD_GIVES_WARN = True      # spam / mass-ping punishments also add a warning
