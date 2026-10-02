import sys
import os
import logging

logger = logging.getLogger(__name__)
from lattice.core.db import get_db_connection
def cmd_events(args):
    logger.info(f"Command cmd_events called with args: {args}")
    if os.geteuid() != 0:
        from lattice.operator_client import request
        params = {"limit": args.n}
        if args.worker:
            params["worker"] = args.worker
        rows = request("events", params)
        if not rows:
            print("No events found.")
            return
        print(f"{'Time':<30} {'Severity':<10} {'Message':<40} {'Worker':<20}")
        for row in rows:
            print(f"{row['timestamp']:<30} {row['severity']:<10} {row['message'][:40]:<40} {row['worker']:<20}")
        return
    conn = get_db_connection()
    cursor = conn.cursor()
    if args.worker:
        cursor.execute(
            "SELECT timestamp, severity, message, worker_id FROM events WHERE worker_id = (SELECT id FROM workers WHERE hostname = ?) ORDER BY timestamp DESC LIMIT ?",
            (args.worker, args.n)
        )
    else:
        cursor.execute("SELECT timestamp, severity, message, worker_id FROM events ORDER BY timestamp DESC LIMIT ?", (args.n,))
    rows = cursor.fetchall()
    conn.close()
    if not rows:
        print("No events found.")
        return
    print(f"{'Time':<30} {'Severity':<10} {'Message':<40} {'Worker':<20}")
    for row in rows:
        # Get worker hostname
        conn2 = get_db_connection()
        cursor2 = conn2.cursor()
        cursor2.execute("SELECT hostname FROM workers WHERE id = ?", (row[3],))
        w = cursor2.fetchone()
        worker_name = w[0] if w else "unknown"
        conn2.close()
        print(f"{row[0]:<30} {row[1]:<10} {row[2][:40]:<40} {worker_name:<20}")