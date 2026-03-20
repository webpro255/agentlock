"""AgentLock CLI — validate schemas, inspect audit logs, manage tools.

Usage::

    agentlock validate tool.json          # Validate a tool definition
    agentlock audit --tool send_email     # Query audit logs
    agentlock schema                      # Print the JSON schema
    agentlock init                        # Generate a starter agentlock.json
    agentlock inspect tool.json           # Display permissions summary
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agentlock import __version__


def _validate(args: argparse.Namespace) -> int:
    """Validate a tool definition file against the AgentLock schema."""
    from pydantic import ValidationError

    from agentlock.schema import AgentLockPermissions, ToolDefinition

    path = Path(args.file)
    if not path.exists():
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 1

    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON: {e}", file=sys.stderr)
        return 1

    errors: list[str] = []

    # If the file is a full tool definition
    if "name" in data:
        try:
            tool = ToolDefinition(**data)
            perms = tool.agentlock
        except ValidationError as e:
            errors.extend(str(err) for err in e.errors())
    elif "agentlock" in data:
        try:
            perms = AgentLockPermissions(**data["agentlock"])
        except ValidationError as e:
            errors.extend(str(err) for err in e.errors())
    else:
        try:
            perms = AgentLockPermissions(**data)
        except ValidationError as e:
            errors.extend(str(err) for err in e.errors())

    if errors:
        print(f"INVALID — {len(errors)} error(s):")
        for err in errors:
            print(f"  {err}")
        return 1

    print(f"VALID — {path.name}")
    print(f"  Version:     {perms.version}")
    print(f"  Risk level:  {perms.risk_level.value}")
    print(f"  Auth:        {'required' if perms.requires_auth else 'not required'}")
    print(f"  Roles:       {', '.join(perms.allowed_roles) or '(none — deny all)'}")
    if perms.rate_limit:
        print(f"  Rate limit:  {perms.rate_limit.max_calls}/{perms.rate_limit.window_seconds}s")
    if perms.data_policy.prohibited_in_output:
        print(f"  Redacts:     {', '.join(perms.data_policy.prohibited_in_output)}")
    if perms.human_approval.required:
        thr = perms.human_approval.threshold.value
        ch = perms.human_approval.channel.value
        print(f"  Approval:    {thr} via {ch}")
    if perms.context_policy is not None:
        cp = perms.context_policy
        td_status = "enabled" if cp.trust_degradation.enabled else "disabled"
        print(f"  Context:     trust_degradation={td_status}")
        print(f"  Reject unattributed: {cp.reject_unattributed}")
    if perms.memory_policy is not None:
        mp = perms.memory_policy
        print(f"  Memory:      persistence={mp.persistence.value}")
        print(f"  Writers:     {', '.join(w.value for w in mp.allowed_writers)}")
    return 0


def _schema(args: argparse.Namespace) -> int:
    """Print the AgentLock JSON schema."""
    from agentlock.schema import AgentLockPermissions

    schema = AgentLockPermissions.model_json_schema()
    print(json.dumps(schema, indent=2))
    return 0


def _init(args: argparse.Namespace) -> int:
    """Generate a starter tool definition with AgentLock permissions."""
    template = {
        "name": "my_tool",
        "description": "Description of what this tool does",
        "parameters": {
            "param1": "string",
            "param2": "integer",
        },
        "agentlock": {
            "version": "1.1",
            "risk_level": "medium",
            "requires_auth": True,
            "auth_methods": ["oauth2"],
            "allowed_roles": ["user", "admin"],
            "scope": {
                "data_boundary": "authenticated_user_only",
                "max_records": 10,
            },
            "rate_limit": {
                "max_calls": 100,
                "window_seconds": 3600,
            },
            "data_policy": {
                "input_classification": "public",
                "output_classification": "internal",
                "prohibited_in_output": [],
                "redaction": "none",
            },
            "audit": {
                "log_level": "standard",
                "include_parameters": True,
                "retention_days": 90,
            },
            "human_approval": {
                "required": False,
            },
        },
    }
    output = Path(args.output) if args.output else Path("agentlock-tool.json")
    output.write_text(json.dumps(template, indent=2) + "\n")
    print(f"Created {output}")
    print("Edit the file and run: agentlock validate " + str(output))
    return 0


def _inspect(args: argparse.Namespace) -> int:
    """Display a human-readable summary of a tool's permissions."""
    path = Path(args.file)
    if not path.exists():
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 1

    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON: {e}", file=sys.stderr)
        return 1

    from pydantic import ValidationError

    from agentlock.schema import AgentLockPermissions

    tool_name = data.get("name", path.stem)

    if "agentlock" in data:
        perms_data = data["agentlock"]
    elif "name" in data:
        perms_data = data.get("agentlock", {})
    else:
        perms_data = data

    try:
        perms = AgentLockPermissions(**perms_data)
    except ValidationError as e:
        print(f"Error: invalid permissions: {e}", file=sys.stderr)
        return 1

    risk_colors = {
        "none": "\033[92m",     # green
        "low": "\033[92m",      # green
        "medium": "\033[93m",   # yellow
        "high": "\033[91m",     # red
        "critical": "\033[91m\033[1m",  # bold red
    }
    reset = "\033[0m"
    rc = risk_colors.get(perms.risk_level.value, "")

    print(f"\n  Tool: {tool_name}")
    print(f"  {'─' * 50}")
    print(f"  Risk:          {rc}{perms.risk_level.value.upper()}{reset}")
    print(f"  Auth required: {'Yes' if perms.requires_auth else 'No'}")
    print(f"  Auth methods:  {', '.join(m.value for m in perms.auth_methods)}")
    print(f"  Allowed roles: {', '.join(perms.allowed_roles) or '(none — DENY ALL)'}")
    print(f"  Data boundary: {perms.scope.data_boundary.value}")
    if perms.scope.max_records:
        print(f"  Max records:   {perms.scope.max_records}")
    if perms.rate_limit:
        rl = perms.rate_limit
        print(f"  Rate limit:    {rl.max_calls} calls / {rl.window_seconds}s")
    print(f"  Input class:   {perms.data_policy.input_classification.value}")
    print(f"  Output class:  {perms.data_policy.output_classification.value}")
    if perms.data_policy.prohibited_in_output:
        types = ", ".join(perms.data_policy.prohibited_in_output)
        mode = perms.data_policy.redaction.value
        print(f"  Redacts:       {types} ({mode})")
    print(f"  Session TTL:   {perms.session.max_duration_seconds}s")
    print(f"  Audit level:   {perms.audit.log_level.value}")
    print(f"  Retention:     {perms.audit.retention_days} days")
    if perms.human_approval.required:
        thr = perms.human_approval.threshold.value
        ch = perms.human_approval.channel.value
        print(f"  Approval:      {thr} via {ch}")
    else:
        print("  Approval:      not required")
    # v1.1 fields
    if perms.context_policy is not None:
        cp = perms.context_policy
        td = cp.trust_degradation
        print("  Context policy:")
        print(f"    Degradation: {'enabled' if td.enabled else 'disabled'}")
        if td.triggers:
            for t in td.triggers:
                print(f"    Trigger:     {t.source.value} → {t.effect.value}")
        print(f"    Reject unattributed: {cp.reject_unattributed}")
    if perms.memory_policy is not None:
        mp = perms.memory_policy
        print("  Memory policy:")
        print(f"    Persistence: {mp.persistence.value}")
        writers = ", ".join(w.value for w in mp.allowed_writers)
        readers = ", ".join(r.value for r in mp.allowed_readers)
        print(f"    Writers:     {writers}")
        print(f"    Readers:     {readers}")
        print(f"    Max entries: {mp.retention.max_entries}")
        print(f"    Max age:     {mp.retention.max_age_seconds}s")
        if mp.prohibited_content:
            prohibited = ", ".join(mp.prohibited_content)
            print(f"    Prohibited:  {prohibited}")
        conf = "required" if mp.require_write_confirmation else "not required"
        print(f"    Confirmation: {conf}")
    print()
    return 0


def _audit_query(args: argparse.Namespace) -> int:
    """Query the audit log."""
    import time

    from agentlock.audit import FileAuditBackend

    path = args.log or str(Path.home() / ".agentlock" / "audit.jsonl")
    backend = FileAuditBackend(path)

    since = None
    if args.since:
        # Parse relative time like "1h", "24h", "7d"
        val = args.since
        if val.endswith("h"):
            since = time.time() - int(val[:-1]) * 3600
        elif val.endswith("d"):
            since = time.time() - int(val[:-1]) * 86400
        elif val.endswith("m"):
            since = time.time() - int(val[:-1]) * 60

    records = backend.query(
        tool_name=args.tool,
        user_id=args.user,
        since=since,
        limit=args.limit,
    )

    if not records:
        print("No audit records found.")
        return 0

    for r in records:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(r.timestamp))
        action_color = "\033[92m" if r.action == "allowed" else "\033[91m"
        reset = "\033[0m"
        print(
            f"  {ts}  {r.audit_id}  {r.tool_name:20s}  "
            f"{action_color}{r.action:8s}{reset}  "
            f"{r.user_id or '-':15s}  {r.role or '-':10s}  "
            f"{r.reason or ''}"
        )

    print(f"\n  {len(records)} record(s)")
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="agentlock",
        description="AgentLock — Authorization framework for AI agent tool calls",
    )
    parser.add_argument(
        "--version", action="version", version=f"agentlock {__version__}"
    )

    sub = parser.add_subparsers(dest="command")

    # validate
    p_validate = sub.add_parser("validate", help="Validate a tool definition")
    p_validate.add_argument("file", help="Path to JSON file")

    # schema
    sub.add_parser("schema", help="Print the AgentLock JSON schema")

    # init
    p_init = sub.add_parser("init", help="Generate a starter tool definition")
    p_init.add_argument("-o", "--output", help="Output path", default=None)

    # inspect
    p_inspect = sub.add_parser("inspect", help="Display permissions summary")
    p_inspect.add_argument("file", help="Path to JSON file")

    # audit
    p_audit = sub.add_parser("audit", help="Query audit logs")
    p_audit.add_argument("--tool", help="Filter by tool name")
    p_audit.add_argument("--user", help="Filter by user ID")
    p_audit.add_argument("--since", help="Time window (e.g. 1h, 24h, 7d)")
    p_audit.add_argument("--limit", type=int, default=50, help="Max records")
    p_audit.add_argument("--log", help="Audit log file path")

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    handlers = {
        "validate": _validate,
        "schema": _schema,
        "init": _init,
        "inspect": _inspect,
        "audit": _audit_query,
    }

    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
