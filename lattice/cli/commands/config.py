import sys
import logging

logger = logging.getLogger(__name__)
import tomli
import tomli_w
from lattice.core.config import CONFIG_PATH, load_config, save_config
_SECRET_FIELDS = {"master.master_key", "master.api_token", "master.telegram_secret", "master.telegram_token"}


def _redacted_config(config):
    payload = config.model_dump()
    for path in _SECRET_FIELDS:
        section, key = path.split(".", 1)
        if payload.get(section, {}).get(key):
            payload[section][key] = "<redacted>"
    channels = payload.get("notifications", {}).get("channels", [])
    for channel in channels:
        cfg = channel.get("config", {}) if isinstance(channel, dict) else {}
        for key in ("password", "token", "secret", "webhook_url"):
            if cfg.get(key):
                cfg[key] = "<redacted>"
    return payload

def cmd_config(args):
    logger.info("Configuration command called for key %s", getattr(args, "key", None))
    if args.action == "get":
        if args.key:
            if args.key in _SECRET_FIELDS:
                print("This secret is protected and is not printed by the CLI.")
                return 1
            config = load_config()
            parts = args.key.split('.')
            obj = config
            try:
                for p in parts:
                    obj = getattr(obj, p)
                print(obj)
            except AttributeError:
                print(f"Key {args.key} not found")
        else:
            # Print the whole config as TOML
            config = load_config()
            import tomli_w
            print(tomli_w.dumps(_redacted_config(config)))
    elif args.action == "set":
        if not args.key or not args.value:
            print("Key and value required for 'set'")
            return
        config = load_config()
        parts = args.key.split('.')
        obj = config
        for p in parts[:-1]:
            obj = getattr(obj, p)
        # Try to convert value
        val = args.value
        # Parse list syntax while the value is still text. The old order
        # converted numbers first and then called .startswith() on an int.
        if val.startswith('[') and val.endswith(']'):
            val = [v.strip().strip('"') for v in val[1:-1].split(',')]
        elif val.isdigit():
            val = int(val)
        elif val.lower() in ("true", "false"):
            val = val.lower() == "true"
        setattr(obj, parts[-1], val)
        save_config(config)
        shown = "<redacted>" if args.key in _SECRET_FIELDS else val
        print(f"Setting {args.key} updated to {shown}")
    else:
        print(f"Unknown action: {args.action}")
