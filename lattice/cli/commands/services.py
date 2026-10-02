
import sys
import logging

logger = logging.getLogger(__name__)
from lattice.core.db import get_db_connection
def cmd_services(args):
    logger.info(f"Command cmd_services called with args: {args}")
    if args.action == "list":
        conn = get_db_connection()
        cursor = conn.cursor()
        if args.worker:
            cursor.execute("SELECT name, status, type FROM services WHERE worker_id=(SELECT id FROM workers WHERE hostname=?)", (args.worker,))
        else:
            cursor.execute("SELECT name, status, type FROM services")
        rows = cursor.fetchall()
        conn.close()
        print(f"{'Name':<20} {'Status':<12} {'Type':<10}")
        for r in rows:
            print(f"{r[0]:<20} {r[1]:<12} {r[2]:<10}")
    elif args.action == "get":
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name, status, type FROM services WHERE name=?", (args.name,))  # H6 fix: removed `unit` (column doesn't exist in current schema)
        row = cursor.fetchone()
        conn.close()
        if row:
            print(f"Name: {row[0]}\nStatus: {row[1]}\nType: {row[2]}")
        else:
            print(f"Service {args.name} not found")
    else:
        print(f"Unknown action: {args.action}")