import logging

logger = logging.getLogger(__name__)

"""
Lattice Error Catalog – stable error codes for all modules.
E001-E099: Config
E101-E199: Network
E201-E299: SSH
E301-E399: Wizard
E401-E499: Auto-heal
E501-E599: IP change
E601-E699: Daemon
E701-E799: API
E801-E899: Notifications
E901-E999: Services
EA01-EA99: Backup/Upgrade (V2)
"""

class LatticeError(Exception):
    """Base exception with error code and message."""
    def __init__(self, code: str, message: str, details: dict = None):
        self.code = code
        self.message = message
        self.details = details or {}
        super().__init__(f"[{code}] {message}")

# ----- Config errors (E001-E099) -----
E001 = "E001"  # config file not found
E002 = "E002"  # config file invalid TOML
E003 = "E003"  # config schema validation failed
E004 = "E004"  # required key missing
E005 = "E005"  # invalid value for key
E006 = "E006"  # config reload failed

# ----- Network errors (E101-E199) -----
E101 = "E101"  # IP already in use
E102 = "E102"  # subnet mismatch
E103 = "E103"  # gateway unreachable
E104 = "E104"  # DHCP lease failed
E105 = "E105"  # no network interface found
E106 = "E106"  # static IP not set
E107 = "E107"  # WiFi disconnect
E108 = "E108"  # DNS resolution failed
E109 = "E109"  # NetworkManager not running

# ----- SSH errors (E201-E299) -----
E201 = "E201"  # SSH connection refused
E202 = "E202"  # SSH auth failed
E203 = "E203"  # SSH host key changed
E204 = "E204"  # SSH timeout
E205 = "E205"  # key already in authorized_keys
E206 = "E206"  # key fingerprint mismatch
E207 = "E207"  # permission denied on authorized_keys

# ----- Wizard errors (E301-E399) -----
E301 = "E301"  # wizard journal corrupt
E302 = "E302"  # wizard step failed
E303 = "E303"  # wizard validation failed
E304 = "E304"  # user cancelled wizard
E305 = "E305"  # non-interactive config file missing
E306 = "E306"  # graduated auth failed

# ----- Auto-heal errors (E401-E499) -----
E401 = "E401"  # circuit breaker open
E402 = "E402"  # action not in allowlist
E403 = "E403"  # hard no-heal category
E404 = "E404"  # max attempts reached
E405 = "E405"  # approval timeout
E406 = "E406"  # service health check failed

# ----- IP change errors (E501-E599) -----
E501 = "E501"  # preflight failed
E502 = "E502"  # apply failed
E503 = "E503"  # revert failed
E504 = "E504"  # DHCP fallback failed
E505 = "E505"  # worker didn't confirm new IP
E506 = "E506"  # boot recovery state corrupt
E507 = "E507"  # magic packet not received

# ----- Daemon errors (E601-E699) -----
E601 = "E601"  # daemon not running
E602 = "E602"  # socket permission denied
E603 = "E603"  # socket timeout
E604 = "E604"  # daemon heartbeat lost
E605 = "E605"  # database locked

# ----- API errors (E701-E799) -----
E701 = "E701"  # auth required
E702 = "E702"  # rate limit exceeded
E703 = "E703"  # worker not found
E704 = "E704"  # service not found
E705 = "E705"  # bad request body
E706 = "E706"  # internal server error
E707 = "E707"  # endpoint not found

# ----- Notification errors (E801-E899) -----
E801 = "E801"  # Telegram bot token invalid
E802 = "E802"  # Telegram API rate limit
E803 = "E803"  # Telegram chat blocked
E804 = "E804"  # webhook URL unreachable
E805 = "E805"  # notification dedup'd
E806 = "E806"  # notification channel disabled

# ----- Service errors (E901-E999) -----
E901 = "E901"  # service not registered
E902 = "E902"  # service restart failed
E903 = "E903"  # service health check timeout
E904 = "E904"  # service log file not found

# ----- Backup/upgrade (EA01-EA99) [V2] -----
EA01 = "EA01"  # backup destination not writable
EA02 = "EA02"  # backup verification failed
EA03 = "EA03"  # upgrade download failed
EA04 = "EA04"  # upgrade checksum mismatch
EA05 = "EA05"  # upgrade rolled back