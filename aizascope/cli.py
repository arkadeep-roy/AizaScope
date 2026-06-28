from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .discovery import update_manifest
from .diagnostics import print_doctor
from .chain_builder import write_attack_chain_outputs
from .http_client import HttpClient
from .input_loader import is_valid_aiza_key, load_key_file, load_single_key
from .models import AUTHOR, TOOL_NAME, VERSION, Finding, ScanContext, mask_key, sha256_text
from .probes import DEFAULT_COLLECTIONS, STORAGE_PREFIXES, ProbeRunner
from .reporter import (
    append_findings_jsonl,
    load_findings_records,
    prepare_output_dirs,
    write_curl_pocs_records,
    write_ready_commands_json_records,
    is_actionable_record,
    proof_commands_for_record,
    write_markdown_report_records,
    write_summary_records,
)
from .state import ScanState
from .term_ui import print_banner, print_run_plan

VALID_PROFILES = {"standard", "active", "aggressive-authorized"}
VALID_RUN_MODES = {"full", "quick", "passive", "custom"}
VALID_AUTH_MODES = {"off", "ask", "auto"}
VALID_WRITE_PROOFS = {"off", "ask", "auto"}
VALID_OPTIONAL_PROOFS = {"off", "ask", "auto"}
VALID_PROMPT_POLICIES = {"once", "per-finding", "never"}
PRIORITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "REVIEW", "LOW", "INFO"]
PRIORITY_RANK = {name: idx for idx, name in enumerate(PRIORITY_ORDER)}
ASK_FIELDS = (
    "auth_mode",
    "write_proof",
    "youtube_expensive_proof",
    "youtube_write_negative_control",
    "gemini_token_proof",
    "gemini_generation_proof",
    "gemini_embed_proof",
    "vision_proof",
    "translation_proof",
    "natural_language_proof",
    "safe_browsing_proof",
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aizascope",
        description="Google/Firebase AIza API-key exploitability triage for authorized bug bounty testing.",
        epilog=(
            "Examples: aizascope keys.txt  |  aizascope --key=AIza...  |  aizascope AIza...  |  "
            "python -m aizascope --key=AIza...  "
            "Default mode is FULL: Firebase + Gemini + YouTube + Maps + Cloud AI. Marker write/delete proof is strictly opt-in with --prove-write."
        ),
    )
    parser.add_argument("target", nargs="?", help="AIza key or TXT file containing one AIza key per line")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--key", metavar="APIKEY", help="Single AIza API key. Supports --key=AIza... and --key AIza...")
    group.add_argument("--file", metavar="PATH", help="TXT file containing only AIza API keys, one per line")

    parser.add_argument("--mode", choices=sorted(VALID_RUN_MODES), default=None, help="Scan preset. Default: full")
    parser.add_argument("--full", dest="mode", action="store_const", const="full", help="Run the full no-prompt aggressive scan preset")
    parser.add_argument("--quick", dest="mode", action="store_const", const="quick", help="Run quick low-cost checks only")
    parser.add_argument("--passive", dest="mode", action="store_const", const="passive", help="Run passive/read-metadata checks only")
    parser.add_argument("--prove-write", action="store_true", help="Opt in to temporary marker write/delete proofs after read/list exposure is confirmed")
    parser.add_argument("--profile", choices=sorted(VALID_PROFILES), default=None, help=argparse.SUPPRESS)

    parser.add_argument("--auth-mode", choices=sorted(VALID_AUTH_MODES), default=None, help=argparse.SUPPRESS)
    parser.add_argument("--write-proof", choices=sorted(VALID_WRITE_PROOFS), default=None, help=argparse.SUPPRESS)
    parser.add_argument("--youtube-expensive-proof", choices=sorted(VALID_OPTIONAL_PROOFS), default=None, help=argparse.SUPPRESS)
    parser.add_argument("--youtube-write-negative-control", choices=sorted(VALID_OPTIONAL_PROOFS), default=None, help=argparse.SUPPRESS)
    parser.add_argument("--gemini-token-proof", choices=sorted(VALID_OPTIONAL_PROOFS), default=None, help=argparse.SUPPRESS)
    parser.add_argument("--gemini-generation-proof", choices=sorted(VALID_OPTIONAL_PROOFS), default=None, help=argparse.SUPPRESS)
    parser.add_argument("--gemini-embed-proof", choices=sorted(VALID_OPTIONAL_PROOFS), default=None, help=argparse.SUPPRESS)
    parser.add_argument("--vision-proof", choices=sorted(VALID_OPTIONAL_PROOFS), default=None, help=argparse.SUPPRESS)
    parser.add_argument("--translation-proof", choices=sorted(VALID_OPTIONAL_PROOFS), default=None, help=argparse.SUPPRESS)
    parser.add_argument("--natural-language-proof", choices=sorted(VALID_OPTIONAL_PROOFS), default=None, help=argparse.SUPPRESS)
    parser.add_argument("--safe-browsing-proof", choices=sorted(VALID_OPTIONAL_PROOFS), default=None, help=argparse.SUPPRESS)

    parser.add_argument("--youtube-search-referrer-matrix", choices=["on", "off"], default=None, help=argparse.SUPPRESS)
    parser.add_argument("--out", default="aizascope_results", help="Output directory")
    parser.add_argument("--concurrency", type=int, default=8, help="Concurrent keys to scan")
    parser.add_argument("--timeout", type=int, default=12, help="HTTP timeout seconds")
    parser.add_argument("--rate-limit", type=float, default=0.0, help=argparse.SUPPRESS)
    parser.add_argument("--store-full-keys", action="store_true", help="Store full API keys in JSONL output instead of masked keys")
    parser.add_argument("--non-interactive", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--yes", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--prompt-policy", choices=sorted(VALID_PROMPT_POLICIES), default="never", help=argparse.SUPPRESS)
    parser.add_argument("--resume", action="store_true", help="Resume from scan_state.json and append to existing findings.jsonl")
    parser.add_argument("--force-rescan", action="store_true", help="Ignore scan_state.json and rescan all keys")
    parser.add_argument("--silent", action="store_true", help="ProjectDiscovery-style concise output: finding lines only plus final file paths")
    parser.add_argument("--jsonl-stdout", action="store_true", help="Print each finding as JSONL to stdout as it is found")
    parser.add_argument("--min-priority", choices=PRIORITY_ORDER, default="MEDIUM", help="Minimum priority to print in live console output")
    parser.add_argument("--user-agent", default=f"{TOOL_NAME}/{VERSION} authorized-bbp-auditor", help=argparse.SUPPRESS)
    parser.add_argument("--update-manifest", action="store_true", help="Fetch Google Discovery API metadata into the output directory and exit")
    parser.add_argument("--doctor", action="store_true", help="Check Python, platform, dependencies, install status, and optional network reachability")
    parser.add_argument("--show-probe-wordlists", action="store_true", help="Show built-in Firestore collection and Storage prefix probe candidates, then exit")
    parser.add_argument("--doctor-network", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--advanced-help", action="store_true", help="Show hidden expert flags and exit")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def print_advanced_help() -> None:
    print("""AizaScope expert flags
======================

Main usage should be simple:
  aizascope keys.txt
  aizascope --key=AIza...
  aizascope AIza...
  aizascope keys.txt --quick
  aizascope keys.txt --passive
  aizascope keys.txt --prove-write
  python -m aizascope --key=AIza...

Hidden expert overrides:
  --prove-write              Temporary marker write/delete proof after confirmed read/list exposure
  --profile standard|active|aggressive-authorized
  --auth-mode off|ask|auto
  --write-proof off|ask|auto
  --youtube-expensive-proof off|ask|auto
  --youtube-write-negative-control off|ask|auto
  --gemini-token-proof off|ask|auto
  --gemini-generation-proof off|ask|auto
  --gemini-embed-proof off|ask|auto
  --vision-proof off|ask|auto
  --translation-proof off|ask|auto
  --natural-language-proof off|ask|auto
  --safe-browsing-proof off|ask|auto
  --youtube-search-referrer-matrix on|off
  --prompt-policy never|once|per-finding
  --yes
  --non-interactive
  --user-agent VALUE

Preset behavior:
  full     Full no-prompt scan. Enables Firebase, Gemini, YouTube, Maps/Places, Cloud AI and anon-auth checks. Marker writes remain off unless --prove-write is used.
  quick    Low-cost active scan. No writes, no expensive YouTube search, no Cloud AI quota probes.
  passive  Metadata/read-only scan.
  custom   Respect the explicit expert overrides above.
""")


def print_probe_wordlists() -> None:
    print("AizaScope built-in probe candidates")
    print("===================================")
    print()
    print("These names are NOT findings by themselves.")
    print("AizaScope uses them as practical bug-bounty probe candidates because Firebase projects do not expose collection names unless listCollectionIds or a guessed collection is readable.")
    print("A finding is emitted only when a documented endpoint returns evidence such as HTTP 200, documents[], prefixes/items, or readable metadata.")
    print()
    print("Firestore collection candidates:")
    for idx, name in enumerate(DEFAULT_COLLECTIONS, 1):
        print(f"  {idx:02d}. {name}")
    print()
    print("Firebase Storage prefix candidates:")
    for idx, name in enumerate(STORAGE_PREFIXES, 1):
        print(f"  {idx:02d}. {name}")
    print()
    print("Marker write/delete paths, used only when --prove-write is explicitly enabled after read/list exposure:")
    print("  Firestore: aizascope_bbp_probe/<nonce>")
    print("  RTDB     : /aizascope_bbp_probe/<nonce>.json")
    print("  Storage  : aizascope_bbp_probe/<nonce>.txt")


def banner(args: argparse.Namespace) -> None:
    print_banner(silent=args.silent, jsonl_stdout=args.jsonl_stdout)


def interactive_input() -> tuple[list[str], list[str]]:
    print("Choose input mode:")
    print("[1] Single AIza API key")
    print("[2] TXT file containing only AIza API keys")
    choice = input("Selection: ").strip()
    if choice == "1":
        key = input("Paste API key: ").strip()
        return load_single_key(key)
    if choice == "2":
        path = input("TXT file path: ").strip().strip('"')
        return load_key_file(path)
    print("Invalid selection.", file=sys.stderr)
    return [], []


def normalize_path_input(value: str) -> str:
    target = value.strip().strip('"').strip("'")
    if is_valid_aiza_key(target):
        return target
    candidate = Path(target).expanduser()
    if candidate.exists():
        return str(candidate)
    if target.startswith("home/"):
        absolute_candidate = Path("/" + target)
        if absolute_candidate.exists():
            return str(absolute_candidate)
    return target


def load_inputs(args: argparse.Namespace) -> tuple[list[str], list[str]]:
    if args.key:
        return load_single_key(args.key)
    if args.file:
        return load_key_file(normalize_path_input(args.file))
    if args.target:
        target = normalize_path_input(args.target)
        if is_valid_aiza_key(target):
            return load_single_key(target)
        return load_key_file(target)
    if args.non_interactive or args.silent or args.jsonl_stdout:
        print("Error: provide an AIza key or key file. Example: aizascope keys.txt", file=sys.stderr)
        return [], []
    return interactive_input()


def _user_selected_advanced_overrides(args: argparse.Namespace) -> bool:
    return bool(
        args.profile
        or any(getattr(args, name) is not None for name in ASK_FIELDS)
        or args.youtube_search_referrer_matrix is not None
    )


def _set_if_missing(args: argparse.Namespace, name: str, value: object) -> None:
    if getattr(args, name) is None:
        setattr(args, name, value)


def apply_execution_policy(args: argparse.Namespace) -> None:
    if args.mode is None:
        args.mode = "custom" if _user_selected_advanced_overrides(args) else "full"

    if args.mode == "full":
        # Main GitHub UX: one command, no prompts, comprehensive active testing.
        _set_if_missing(args, "profile", "aggressive-authorized")
        _set_if_missing(args, "auth_mode", "auto")
        _set_if_missing(args, "write_proof", "off")
        _set_if_missing(args, "youtube_expensive_proof", "auto")
        _set_if_missing(args, "youtube_write_negative_control", "auto")
        _set_if_missing(args, "gemini_token_proof", "auto")
        _set_if_missing(args, "gemini_generation_proof", "auto")
        _set_if_missing(args, "gemini_embed_proof", "auto")
        _set_if_missing(args, "vision_proof", "auto")
        _set_if_missing(args, "translation_proof", "auto")
        _set_if_missing(args, "natural_language_proof", "auto")
        _set_if_missing(args, "safe_browsing_proof", "auto")
        _set_if_missing(args, "youtube_search_referrer_matrix", "on")
        args.prompt_policy = "never"
        args.non_interactive = True
    elif args.mode == "quick":
        _set_if_missing(args, "profile", "active")
        _set_if_missing(args, "auth_mode", "off")
        _set_if_missing(args, "write_proof", "off")
        _set_if_missing(args, "youtube_expensive_proof", "off")
        _set_if_missing(args, "youtube_write_negative_control", "auto")
        _set_if_missing(args, "gemini_token_proof", "auto")
        _set_if_missing(args, "gemini_generation_proof", "off")
        _set_if_missing(args, "gemini_embed_proof", "auto")
        _set_if_missing(args, "vision_proof", "off")
        _set_if_missing(args, "translation_proof", "off")
        _set_if_missing(args, "natural_language_proof", "off")
        _set_if_missing(args, "safe_browsing_proof", "auto")
        _set_if_missing(args, "youtube_search_referrer_matrix", "on")
        args.prompt_policy = "never"
        args.non_interactive = True
    elif args.mode == "passive":
        _set_if_missing(args, "profile", "standard")
        for name in ASK_FIELDS:
            _set_if_missing(args, name, "off")
        _set_if_missing(args, "youtube_search_referrer_matrix", "on")
        args.prompt_policy = "never"
        args.non_interactive = True
    else:
        _set_if_missing(args, "profile", "standard")
        for name in ASK_FIELDS:
            _set_if_missing(args, name, "off")
        _set_if_missing(args, "youtube_search_referrer_matrix", "on")

    if getattr(args, "prove_write", False):
        args.write_proof = "auto"
        if args.profile == "standard":
            args.profile = "aggressive-authorized"

    if args.yes:
        for name in ASK_FIELDS:
            if getattr(args, name) == "ask":
                setattr(args, name, "auto")
    if args.non_interactive or args.prompt_policy == "never":
        for name in ASK_FIELDS:
            if getattr(args, name) == "ask":
                setattr(args, name, "off")
        args.non_interactive = True


def scan_key(key: str, args: argparse.Namespace, prompt_decisions: dict[str, bool] | None = None) -> list[Finding]:
    client = HttpClient(timeout=args.timeout, user_agent=args.user_agent)
    runner = ProbeRunner(client)
    ctx = ScanContext(
        key=key,
        profile=args.profile,
        auth_mode=args.auth_mode,
        write_proof=args.write_proof,
        non_interactive=args.non_interactive,
        store_full_key=args.store_full_keys,
        timeout=args.timeout,
        user_agent=args.user_agent,
        output_dir=args.out,
        youtube_expensive_proof=args.youtube_expensive_proof,
        youtube_write_negative_control=args.youtube_write_negative_control,
        gemini_token_proof=args.gemini_token_proof,
        gemini_generation_proof=args.gemini_generation_proof,
        vision_proof=args.vision_proof,
        translation_proof=args.translation_proof,
        natural_language_proof=args.natural_language_proof,
        gemini_embed_proof=args.gemini_embed_proof,
        safe_browsing_proof=args.safe_browsing_proof,
        youtube_search_referrer_matrix=(args.youtube_search_referrer_matrix == "on"),
        prompt_policy=args.prompt_policy,
        prompt_decisions=prompt_decisions if prompt_decisions is not None else {},
    )
    return runner.run_all(ctx)


def priority_at_or_above(priority: str, min_priority: str) -> bool:
    return PRIORITY_RANK.get(priority, 99) <= PRIORITY_RANK.get(min_priority, 2)


def should_print_record(record: dict[str, object], min_priority: str) -> bool:
    return is_actionable_record(record, min_priority=min_priority)


def _detail_summary(record: dict[str, object]) -> str:
    details = record.get("details") if isinstance(record.get("details"), dict) else {}
    parts: list[str] = []
    if record.get("project_id"):
        parts.append(f"project={record.get('project_id')}")
    if record.get("target"):
        parts.append(f"target={record.get('target')}")
    if record.get("http_status") is not None:
        parts.append(f"status={record.get('http_status')}")
    if isinstance(details, dict):
        referrer = details.get("referrer_matrix")
        if isinstance(referrer, dict):
            wins = [str(k) for k, v in referrer.items() if v in {200, 204}]
            if wins:
                parts.append("allowed=" + ",".join(wins))
        if details.get("model"):
            parts.append(f"model={details.get('model')}")
        if details.get("documents_returned") is not None:
            parts.append(f"docs={details.get('documents_returned')}")
        if details.get("objects_or_prefixes_sample_count") is not None:
            parts.append(f"objects_or_prefixes={details.get('objects_or_prefixes_sample_count')}")
        if details.get("top_level_key_count") is not None:
            parts.append(f"top_level_keys={details.get('top_level_key_count')}")
    return " ".join(parts)


def format_finding_record(record: dict[str, object]) -> str:
    extra = _detail_summary(record)
    extra = f" {extra}" if extra else ""
    return (
        f"[{record.get('suggested_priority')}] "
        f"{record.get('classification')} "
        f"service={record.get('service')} "
        f"method={record.get('method_name')} "
        f"key={record.get('api_key')}"
        f"{extra}"
    )


def emit_live_findings(findings: list[Finding], args: argparse.Namespace) -> None:
    for finding in findings:
        record = finding.to_dict(store_full_key=args.store_full_keys)
        if args.jsonl_stdout:
            print(json.dumps(record, ensure_ascii=False, sort_keys=True), flush=True)
        elif should_print_record(record, args.min_priority):
            print(format_finding_record(record), flush=True)



def print_single_key_poc_commands(records: list[dict[str, object]], key: str, args: argparse.Namespace) -> None:
    """Print ready-to-run PoC commands directly on terminal for single-key scans."""
    if args.silent or args.jsonl_stdout:
        return

    min_priority = getattr(args, "min_priority", "MEDIUM")
    actionable = [
        record for record in records
        if is_actionable_record(record, min_priority=min_priority)
    ]
    printed: set[str] = set()
    command_blocks: list[tuple[dict[str, object], list[str]]] = []
    for record in actionable:
        commands = proof_commands_for_record(record, key)
        unique_commands = []
        for command in commands:
            if command not in printed:
                printed.add(command)
                unique_commands.append(command)
        if unique_commands:
            command_blocks.append((record, unique_commands))

    print()
    print("Ready-to-run PoC commands")
    print("=========================")
    if not command_blocks:
        print(f"No {min_priority}+ ready-to-run PoC commands generated for this key.")
        return

    print("The commands below embed the key you provided. Redact the key before using them in public reports.")
    print()
    for record, commands in command_blocks:
        print(f"# [{record.get('suggested_priority')}] {record.get('classification')} - {record.get('service')} - {record.get('method_name')}")
        for command in commands:
            print(command)
        print()

def print_console_summary(records: list[dict[str, object]], args: argparse.Namespace) -> None:
    if args.jsonl_stdout:
        return

    visible = [record for record in records if should_print_record(record, args.min_priority)]
    if args.silent:
        return

    print()
    print(f"Actionable findings shown ({args.min_priority}+)")
    print("=" * (len(args.min_priority) + 29))
    if not visible:
        print(f"No actionable {args.min_priority}+ findings confirmed on terminal output.")
        print(f"Detailed raw records saved: {len(records)}")
        return

    counts = {priority: 0 for priority in PRIORITY_ORDER}
    for record in visible:
        priority = str(record.get("suggested_priority") or "INFO")
        counts[priority] = counts.get(priority, 0) + 1
    for priority in PRIORITY_ORDER:
        if counts.get(priority) and priority_at_or_above(priority, args.min_priority):
            print(f"{priority}: {counts[priority]}")

    print()
    print("Findings")
    print("--------")

    def sort_key(record: dict[str, object]) -> tuple[int, str, str]:
        return (
            PRIORITY_RANK.get(str(record.get("suggested_priority") or "INFO"), 99),
            str(record.get("service") or ""),
            str(record.get("classification") or ""),
        )

    for record in sorted(visible, key=sort_key)[:50]:
        print(format_finding_record(record))
    if len(visible) > 50:
        print(f"... {len(visible) - 50} more actionable findings in findings.jsonl")
    print(f"Detailed raw records saved: {len(records)}")


def reset_outputs_if_needed(args: argparse.Namespace, state: ScanState) -> None:
    paths = prepare_output_dirs(args.out)
    findings_path = paths["root"] / "findings.jsonl"
    if args.force_rescan or not args.resume:
        if findings_path.exists():
            findings_path.unlink()
        state.reset()


def print_run_config(args: argparse.Namespace, keys_count: int) -> None:
    print_run_plan(
        mode=args.mode,
        keys_count=keys_count,
        concurrency=args.concurrency,
        output=args.out,
        silent=args.silent,
        jsonl_stdout=args.jsonl_stdout,
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.advanced_help:
        print_advanced_help()
        return 0
    if args.show_probe_wordlists:
        print_probe_wordlists()
        return 0
    if args.doctor:
        return print_doctor(check_network=args.doctor_network)
    banner(args)

    if args.update_manifest:
        path = update_manifest(args.out, timeout=args.timeout, user_agent=args.user_agent)
        print(f"Discovery manifest written: {path}")
        return 0

    apply_execution_policy(args)

    try:
        keys, invalid = load_inputs(args)
    except OSError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2
    all_input_keys = list(keys)
    if invalid:
        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        invalid_path = out_dir / "invalid_keys.txt"
        invalid_path.write_text("\n".join(invalid) + "\n", encoding="utf-8")
        if not args.silent and not args.jsonl_stdout:
            print(f"Invalid lines saved: {invalid_path}")

    if not keys:
        print("No valid AIza keys found.", file=sys.stderr)
        return 2

    state = ScanState(args.out)
    reset_outputs_if_needed(args, state)
    if args.resume and not args.force_rescan:
        before = len(keys)
        keys = [key for key in keys if not state.is_completed(key)]
        skipped = before - len(keys)
        if skipped and not args.silent and not args.jsonl_stdout:
            print(f"Resume: skipped completed keys: {skipped}")

    print_run_config(args, len(keys))

    prompt_decisions: dict[str, bool] = {}
    has_ask = any(getattr(args, name) == "ask" for name in ASK_FIELDS)
    sequential = len(keys) == 1 or args.concurrency <= 1 or (has_ask and not args.yes and not args.non_interactive)

    if sequential:
        for idx, key in enumerate(keys, start=1):
            if not args.silent and not args.jsonl_stdout:
                print(f"[{idx}/{len(keys)}] Scanning {mask_key(key)}")
            try:
                findings = scan_key(key, args, prompt_decisions)
                append_findings_jsonl(findings, args.out, store_full_key=args.store_full_keys)
                state.mark_completed(key, len(findings))
                emit_live_findings(findings, args)
                if not args.silent and not args.jsonl_stdout:
                    print(f"[{idx}/{len(keys)}] Completed {mask_key(key)} actionable={sum(1 for f in findings if should_print_record(f.to_dict(store_full_key=args.store_full_keys), args.min_priority))}")
            except KeyboardInterrupt:
                print("\nInterrupted. Use --resume to continue from scan_state.json.", file=sys.stderr)
                return 130
            except Exception as exc:
                state.mark_failed(key, f"{type(exc).__name__}: {exc}")
                print(f"Error scanning {mask_key(key)}: {type(exc).__name__}: {exc}", file=sys.stderr)
    else:
        with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as pool:
            future_map = {pool.submit(scan_key, key, args, prompt_decisions): key for key in keys}
            for idx, future in enumerate(as_completed(future_map), start=1):
                key = future_map[future]
                try:
                    findings = future.result()
                    append_findings_jsonl(findings, args.out, store_full_key=args.store_full_keys)
                    state.mark_completed(key, len(findings))
                    emit_live_findings(findings, args)
                    if not args.silent and not args.jsonl_stdout:
                        print(f"[{idx}/{len(keys)}] Completed {mask_key(key)} actionable={sum(1 for f in findings if should_print_record(f.to_dict(store_full_key=args.store_full_keys), args.min_priority))}")
                except Exception as exc:
                    state.mark_failed(key, f"{type(exc).__name__}: {exc}")
                    print(f"Error scanning {mask_key(key)}: {type(exc).__name__}: {exc}", file=sys.stderr)

    records = load_findings_records(args.out)
    summary_path = write_summary_records(records, args.out)
    report_path = write_markdown_report_records(records, args.out)
    key_by_hash = {sha256_text(key): key for key in all_input_keys}
    poc_path = write_curl_pocs_records(records, args.out, key_by_hash=key_by_hash)
    proof_json_path = write_ready_commands_json_records(records, args.out, key_by_hash=key_by_hash)
    _chains_json_path, chains_md_path = write_attack_chain_outputs(records, args.out)
    findings_path = Path(args.out) / "findings.jsonl"

    print_console_summary(records, args)
    if len(all_input_keys) == 1:
        print_single_key_poc_commands(records, all_input_keys[0], args)
    if not args.jsonl_stdout:
        print()
        print("Files written")
        print("-------------")
        print(f"Raw JSONL:        {findings_path}")
        print(f"Summary JSON:     {summary_path}")
        print(f"Advisory report:  {report_path}")
        print(f"PoC shell script: {poc_path}")
        print(f"PoC JSON:         {proof_json_path}")
        print(f"Attack chains:    {chains_md_path}")
        print(f"Resume state:     {Path(args.out) / 'scan_state.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
