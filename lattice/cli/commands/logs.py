
import subprocess
import logging

logger = logging.getLogger(__name__)
def cmd_logs(args):
    logger.info(f"Command cmd_logs called with args: {args}")
    cmd = ["journalctl", "-u", "lattice-master", "-n", str(args.n)]
    if args.follow:
        cmd.append("-f")
    try:
        subprocess.run(cmd, timeout=30,)
    except KeyboardInterrupt:
        pass