import sys
import os
import logging

logger = logging.getLogger(__name__)
from lattice.core.db import get_db_connection
from lattice.core.events import acknowledge_alert, get_active_alerts
def cmd_alerts(args):
    logger.info(f"Command cmd_alerts called with args: {args}")
    if args.action == "list":
        if os.geteuid() == 0:
            alerts = get_active_alerts()
        else:
            from lattice.operator_client import request
            alerts = request("alerts.list")
        if not alerts:
            print("No active alerts.")
            return
        print(f"{'ID':<6} {'Severity':<10} {'Title':<30} {'Worker':<20} {'Fired':<20}")
        for a in alerts:
            worker_name = a.get('worker', 'unknown')
            print(f"{a['id']:<6} {a['severity']:<10} {a['title']:<30} {worker_name:<20} {a['fired_at']:<20}")
    elif args.action == "get":
        if not args.id:
            print("Alert ID required for 'get'")
            return
        if os.geteuid() != 0:
            from lattice.operator_client import request
            row = request("alerts.get", {"alert_id": args.id})
            if row:
                print(f"ID: {row['id']}\nSeverity: {row['severity']}\nTitle: {row['title']}\nMessage: {row['message']}\nFired: {row['fired_at']}\nWorker: {row['worker']}")
            else:
                print(f"Alert {args.id} not found")
            return
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, severity, title, message, fired_at, worker_id FROM alerts WHERE id = ?", (args.id,))
        row = cursor.fetchone()
        conn.close()
        if row:
            # Get worker hostname
            conn2 = get_db_connection()
            cursor2 = conn2.cursor()
            cursor2.execute("SELECT hostname FROM workers WHERE id = ?", (row[5],))
            w = cursor2.fetchone()
            conn2.close()
            worker_name = w[0] if w else "unknown"
            print(f"ID: {row[0]}\nSeverity: {row[1]}\nTitle: {row[2]}\nMessage: {row[3]}\nFired: {row[4]}\nWorker: {worker_name}")
        else:
            print(f"Alert {args.id} not found")
    elif args.action == "ack":
        if not args.id:
            print("Alert ID required for 'ack'")
            return
        if acknowledge_alert(args.id):
            print(f"Alert {args.id} acknowledged")
        else:
            print(f"Alert {args.id} not found or already resolved")
    else:
        print(f"Unknown action: {args.action}")