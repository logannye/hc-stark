#!/usr/bin/env python3
"""Review the no-email evaluation application ledger.

Contact details are redacted unless ``--include-contact`` is supplied.
Purging is a dry run unless ``--apply`` is supplied.
"""

from __future__ import annotations

import argparse
import json
import sys

import evaluation_store


def _print(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", help="Override HC_EVALUATION_STORE_PATH")
    sub = parser.add_subparsers(dest="command", required=True)

    list_parser = sub.add_parser("list", help="List applications")
    list_parser.add_argument("--status", choices=sorted(evaluation_store.VALID_STATUSES))
    list_parser.add_argument("--include-contact", action="store_true")

    show_parser = sub.add_parser("show", help="Show one application")
    show_parser.add_argument("application_id")
    show_parser.add_argument("--include-contact", action="store_true")

    status_parser = sub.add_parser("set-status", help="Update workflow status")
    status_parser.add_argument("application_id")
    status_parser.add_argument("status", choices=sorted(evaluation_store.VALID_STATUSES))

    purge_parser = sub.add_parser("purge-expired", help="Enforce the retention deadline")
    purge_parser.add_argument("--apply", action="store_true")

    args = parser.parse_args(argv)
    if args.command == "list":
        _print(
            evaluation_store.list_applications(
                status=args.status,
                include_contact=args.include_contact,
                path=args.db,
            )
        )
        return 0
    if args.command == "show":
        record = evaluation_store.get_application(
            args.application_id,
            include_contact=args.include_contact,
            path=args.db,
        )
        if record is None:
            print("application not found", file=sys.stderr)
            return 2
        _print(record)
        return 0
    if args.command == "set-status":
        if not evaluation_store.set_status(
            args.application_id,
            args.status,
            path=args.db,
        ):
            print("application not found", file=sys.stderr)
            return 2
        _print({"application_id": args.application_id, "status": args.status})
        return 0

    ids = evaluation_store.expired_ids(path=args.db)
    if not args.apply:
        _print({"apply": False, "expired_count": len(ids), "application_ids": ids})
        return 0
    deleted = evaluation_store.purge_expired(path=args.db)
    _print({"apply": True, "deleted": deleted})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
