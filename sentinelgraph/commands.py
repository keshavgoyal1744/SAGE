"""Slash-command dispatcher for provider comments and chat-style triggers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List

from .models import (
    FullSecurityAuditRequest,
    MemoryAskRequest,
    MemorySyncRequest,
    PolicyAuditRequest,
    RemediationVerificationRequest,
    ReplyCommandInput,
    ScannerChaosRequest,
    SlashCommandRequest,
    VulnerabilityTriageRequest,
)

if TYPE_CHECKING:
    from .factory import Engines


COMMAND_PREFIXES = ("/sentinelgraph", "/sg")


def is_slash_command(text: str) -> bool:
    stripped = text.strip().lower()
    return any(stripped.startswith(prefix) for prefix in COMMAND_PREFIXES)


def dispatch_slash_command(engines: "Engines", item: SlashCommandRequest) -> Dict[str, object]:
    tokens = tokenize_command(item.command or item.body)
    if not tokens:
        return {"status": "ignored", "reason": "empty command"}
    action = tokens[0]
    args = tokens[1:]
    common = {
        "provider": item.provider,
        "repo": item.repo,
        "token": item.token,
        "token_env": item.token_env,
        "base_url": item.base_url,
        "dry_run": item.dry_run,
        "trigger_change_id": item.trigger_change_id,
        "trigger_issue_id": item.trigger_issue_id,
    }
    if action in {"full-audit", "audit", "run"}:
        result = engines.full_security_audit.run(FullSecurityAuditRequest(**common, default_branch=item.default_branch))
    elif action in {"scanner", "scanner-validation"}:
        result = engines.scanner_chaos.run(ScannerChaosRequest(**common))
    elif action in {"policy", "policy-audit"}:
        result = engines.policy_audit.audit(PolicyAuditRequest(**common, default_branch=item.default_branch))
    elif action in {"triage", "triage-vulnerabilities"}:
        result = engines.vulnerability_triage.run(VulnerabilityTriageRequest(**common, default_branch=item.default_branch))
    elif action in {"verify", "verify-remediation"}:
        result = engines.remediation_verification.run(RemediationVerificationRequest(**common, default_branch=item.default_branch))
    elif action in {"sync-memory", "memory-sync"}:
        result = engines.memory_suite.sync(MemorySyncRequest(**common, external_target="both"))
    elif action in {"validate-memory", "memory-validate"}:
        result = engines.memory_suite.validate()
    elif action == "ask":
        result = engines.memory_suite.ask(MemoryAskRequest(question=" ".join(args), repo=item.repo))
    elif action in {"intentional", "accidental", "discuss"}:
        if not args:
            return {"status": "error", "message": f"{action} requires a decision id"}
        result = engines.memory_suite.reply(
            ReplyCommandInput(
                repo=item.repo,
                decision_id=args[0],
                command=action,
                reasoning=" ".join(args[1:]),
                actor=item.actor,
            )
        )
    else:
        return {
            "status": "unknown-command",
            "action": action,
            "supported": [
                "full-audit",
                "scanner",
                "policy",
                "triage",
                "verify",
                "sync-memory",
                "validate-memory",
                "ask",
                "intentional",
                "accidental",
                "discuss",
            ],
        }
    return {"status": "executed", "action": action, "result": result}


def tokenize_command(text: str) -> List[str]:
    stripped = text.strip()
    for prefix in COMMAND_PREFIXES:
        if stripped.lower().startswith(prefix):
            stripped = stripped[len(prefix) :].strip()
            break
    return stripped.split()
