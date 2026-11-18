#!/usr/bin/env python3
"""PromptShield's initial prompt-injection detection runner.

This is a deliberately small, explainable scaffold. It uses local regular
expression rules to flag common prompt-injection indicators; it is not a
security boundary, a model-quality judge, or a complete injection detector.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence


__version__ = "0.2.0"


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    severity: str
    description: str
    patterns: tuple[str, ...]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    severity: str
    description: str
    evidence: str


RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="PS-INJ-001",
        category="instruction_override",
        severity="high",
        description="Attempts to replace, ignore, or supersede trusted instructions.",
        patterns=(
            r"\b(ignore|disregard|forget|override|bypass)\b.{0,80}\b(previous| prior| earlier| system| developer|all)\b.{0,40}\b(instructions?|rules?|messages?)\b",
            r"\b(new|updated|real|actual)\s+(system|developer)\s+(prompt|instructions?)\b",
        ),
    ),
    Rule(
        rule_id="PS-INJ-002",
        category="prompt_exfiltration",
        severity="high",
        description="Requests hidden prompts, internal policies, or protected reasoning.",
        patterns=(
            r"\b(reveal|show|print|expose|leak|repeat| tell me)\b.{0,60}\b(system prompt|developer message|hidden instructions?|internal policy|chain[- ]of[- ]thought)\b",
            r"\bwhat are your\s+(system|hidden|internal)\s+(instructions?|rules?|prompt)\b",
        ),
    ),
    Rule(
        rule_id="PS-INJ-003",
        category="jailbreak",
        severity="medium",
        description="Attempts to change the assistant's operating persona or safety constraints.",
        patterns=(
            r"\b(you are now|act as|roleplay as|pretend to be)\b.{0,80}\b(unrestricted|unfiltered|developer mode|dan|no rules?)\b",
            r"\b(disable|remove|turn off)\b.{0,40}\b(safety|guardrails?|content filters?)\b",
        ),
    ),
    Rule(
        rule_id="PS-INJ-004",
        category="unsafe_action_request",
        severity="medium",
        description="Attempts to force an action or tool call outside the stated task constraints.",
        patterns=(
            r"\b(send|transfer|delete|execute|run|call)\b.{0,60}\b(without|no|skip)\b.{0,30}\b(approval|confirmation|authorization|validation)\b",
            r"\b(do not ask|don't ask|skip confirmation)\b",
        ),
    ),
    Rule(
        rule_id="PS-INJ-005",
        category="multi_step_escalation",
        severity="high",
        description="Uses staged instructions to establish trust, change operating rules, and then request a protected action.",
        patterns=(
            r"\b(first|step\s*1|stage\s*1)\b.{0,180}\b(then|next|after that|step\s*2|stage\s*2)\b.{0,180}\b(ignore|override|reveal|disable|execute|send|delete)\b",
            r"\b(acknowledge|confirm|agree)\b.{0,100}\b(you are|you will be|from now on)\b.{0,100}\b(unrestricted|unfiltered|no rules?|ignore)\b",
        ),
    ),
    Rule(
        rule_id="PS-INJ-006",
        category="delimiter_or_context_attack",
        severity="high",
        description="Embeds a new instruction inside a quoted, delimited, or document-like context to confuse instruction boundaries.",
        patterns=(
            r"(?:```|<\s*(system|developer|instruction|message)\s*>|\[\s*(system|developer|instruction)\s*\]).{0,220}\b(ignore|override|reveal|follow these instructions|disregard)\b",
            r"\b(end of (document|context|conversation))\b.{0,100}\b(new instructions?|ignore|override|execute)\b",
        ),
    ),
    Rule(
        rule_id="PS-INJ-007",
        category="indirect_injection",
        severity="high",
        description="Treats content from a document, webpage, email, or retrieved source as an instruction to the assistant.",
        patterns=(
            r"\b(the following|this)\s+(document|webpage|email|search result|retrieved text|file)\b.{0,160}\b(instructs?|tells?|commands?|says)\b.{0,120}\b(ignore|reveal|send|execute|follow)\b",
            r"\b(when you read|after reading|upon viewing)\b.{0,120}\b(follow|obey|execute|ignore|reveal)\b.{0,80}\b(instructions?|commands?|directions?)\b",
        ),
    ),
    Rule(
        rule_id="PS-INJ-008",
        category="authority_escalation",
        severity="medium",
        description="Claims a special testing, debugging, or administrative role to bypass normal safeguards.",
        patterns=(
            r"\b(for (testing|debugging|research|an audit)|internal (test|testing|audit)|authorized developer)\b.{0,140}\b(disable|bypass|ignore|turn off|reveal)\b.{0,80}\b(safety|guardrails?|filters?|instructions?|prompt)\b",
            r"\b(admin|root|developer|system)\s+(override|mode|access)\b.{0,100}\b(no restrictions?|unrestricted|bypass|disable)\b",
        ),
    ),
    Rule(
        rule_id="PS-INJ-009",
        category="encoded_or_obfuscated_instruction",
        severity="medium",
        description="Requests decoding or transformation of concealed content followed by execution as an instruction.",
        patterns=(
            r"\b(decode|decrypt|base64|rot13|hex|unicode|encoded)\b.{0,100}\b(and|then)\b.{0,100}\b(execute|follow|obey|run|treat as instructions?)\b",
            r"\b(translate|convert|reverse|decode)\b.{0,100}\b(the hidden|the secret|this payload)\b.{0,100}\b(ignore|reveal|disable|execute)\b",
        ),
    ),
    Rule(
        rule_id="PS-INJ-010",
        category="instruction_persistence",
        severity="medium",
        description="Attempts to plant durable instructions in memory, preferences, summaries, or future context.",
        patterns=(
            r"\b(remember|store|save|write)\b.{0,100}\b(this|the following)\b.{0,100}\b(as (a )?(system|developer) instruction|for all future requests?|permanently)\b",
            r"\b(update|change|modify)\b.{0,100}\b(memory|profile|preferences?|conversation summary)\b.{0,100}\b(ignore|reveal|bypass|always)\b",
        ),
    ),
    Rule(
        rule_id="PS-INJ-011",
        category="tool_chain_escalation",
        severity="high",
        description="Chains multiple tool or data actions to reach a sensitive outcome without explicit authorization.",
        patterns=(
            r"\b(first|then|next)\b.{0,160}\b(search|read|fetch|list|query)\b.{0,160}\b(then|next|after that)\b.{0,160}\b(send|upload|transfer|delete|execute|exfiltrate)\b",
            r"\b(use|call|invoke)\b.{0,100}\b(tool|function|api)\b.{0,120}\b(to|and then)\b.{0,120}\b(send|upload|delete|execute|exfiltrate)\b",
        ),
    ),
)


def _compile_rules(rules: Sequence[Rule]) -> tuple[tuple[Rule, tuple[re.Pattern[str], ...]], ...]:
    return tuple((rule, tuple(re.compile(pattern, re.IGNORECASE | re.DOTALL) for pattern in rule.patterns)) for rule in rules)


COMPILED_RULES = _compile_rules(RULES)


def _evidence(text: str, match: re.Match[str], radius: int = 90) -> str:
    start = max(0, match.start() - radius)
    end = min(len(text), match.end() + radius)
    return " ".join(text[start:end].split())


def scan_text(text: str) -> list[Finding]:
    """Return one finding per matched rule, preserving rule order."""
    findings: list[Finding] = []
    for rule, patterns in COMPILED_RULES:
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        category=rule.category,
                        severity=rule.severity,
                        description=rule.description,
                        evidence=_evidence(text, match),
                    )
                )
                break
    return findings


def scan_records(records: Iterable[dict]) -> list[dict]:
    """Scan JSONL records containing an ``id`` and ``prompt`` field."""
    results: list[dict] = []
    for line_number, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            raise ValueError(f"JSONL line {line_number} must be an object")
        prompt = record.get("prompt")
        if not isinstance(prompt, str):
            raise ValueError(f"JSONL line {line_number} must contain a string 'prompt'")
        findings = scan_text(prompt)
        results.append(
            {
                "id": record.get("id", f"line-{line_number}"),
                "detected": bool(findings),
                "finding_count": len(findings),
                "findings": [asdict(finding) for finding in findings],
            }
        )
    return results


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run local, explainable PromptShield prompt-injection checks.",
        epilog=(
            "Examples: %(prog)s --text 'Summarize this report.'; "
            "%(prog)s --file prompt.txt --json; "
            "cat prompt.txt | %(prog)s --stdin"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    source = parser.add_mutually_exclusive_group(required=False)
    source.add_argument("--text", help="Prompt text to scan.")
    source.add_argument("--file", type=Path, help="UTF-8 text file containing one prompt.")
    source.add_argument("--jsonl", type=Path, help="JSONL file with {id, prompt} records.")
    source.add_argument("--stdin", action="store_true", help="Read one prompt from standard input.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    parser.add_argument("--quiet", action="store_true", help="Suppress human-readable findings.")
    parser.add_argument("--list-rules", action="store_true", help="List enabled rules and exit.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _human_prompt_result(findings: list[Finding]) -> str:
    if not findings:
        return "PASS: no basic prompt-injection indicators detected."
    lines = [f"DETECTED: {len(findings)} basic prompt-injection indicator(s)."]
    for finding in findings:
        lines.append(f"- {finding.rule_id} [{finding.severity}] {finding.category}: {finding.description}")
        lines.append(f"  Evidence: {finding.evidence}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.list_rules:
        rules = [
            {
                "rule_id": rule.rule_id,
                "category": rule.category,
                "severity": rule.severity,
                "description": rule.description,
            }
            for rule in RULES
        ]
        if args.json:
            print(json.dumps(rules, indent=2))
        elif not args.quiet:
            for rule in rules:
                print(f"{rule['rule_id']} [{rule['severity']}] {rule['category']}: {rule['description']}")
        return 0

    if not any((args.text is not None, args.file is not None, args.jsonl is not None, args.stdin)):
        parser.error("one input source is required: --text, --file, --jsonl, or --stdin")

    try:
        if args.jsonl:
            records = []
            with args.jsonl.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if not line.strip():
                        continue
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError as exc:
                        raise ValueError(f"JSONL line {line_number} is invalid: {exc}") from exc
            results = scan_records(records)
            if args.json:
                print(json.dumps(results, indent=2))
            elif not args.quiet:
                for result in results:
                    print(f"{result['id']}: {_human_prompt_result([Finding(**finding) for finding in result['findings']])}")
            return 1 if any(result["detected"] for result in results) else 0

        if args.stdin:
            text = sys.stdin.read()
        elif args.text is not None:
            text = args.text
        else:
            text = args.file.read_text(encoding="utf-8")
        findings = scan_text(text)
        if args.json:
            print(json.dumps({"detected": bool(findings), "finding_count": len(findings), "findings": [asdict(f) for f in findings]}, indent=2))
        elif not args.quiet:
            print(_human_prompt_result(findings))
        return 1 if findings else 0
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
