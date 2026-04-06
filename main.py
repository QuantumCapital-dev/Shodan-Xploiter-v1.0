#!/usr/bin/env python3
"""
Shodan Xploiter v1.0
====================
OSINT IP analysis tool with three-phase AI reporting.
Combines Shodan + IPInfo + WHOIS with Claude-powered intelligence reports.

Created by Quantum Capital (www.quantumcapital.capital)

Usage:
    python main.py
    python main.py --no-ai
    python main.py --output-dir /tmp/reports

"""

import argparse
import json
import time
import sys
import random
import threading
from typing import Optional, Tuple
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich import box

import config
from collectors import whois_collector, ipinfo_collector, shodan_collector
from analysis.ai_provider import get_provider, HAIKU_MODEL, SONNET_MODEL
from analysis import prompts
from output import report_writer

console = Console()

# -----------------------------------------------------------------------------
# SHODAN XPLOITER -- terminal logo
# -----------------------------------------------------------------------------

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
BLINK  = "\033[5m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
GRAY   = "\033[90m"

LOGO_LINES = [
    r" _____ _   _  ___  ____    _    _   _ ",
    r"/  ___| | | |/ _ \|  _ \  / \  | \ | |",
    r"\ `--.| |_| | | | | | | |/ _ \ |  \| |",
    r" `--. \  _  | |_| | |_| / ___ \| |\  |",
    r"\____/_| |_|\___/|____/_/   \_\_| \_|",
]

XPLOITER_LINES = [
    r"__  ______  _      ___  ___ _____ _____ ____  ",
    r"\ \/ /  _ \| |    / _ \|_ _|_   _| ____|  _ \ ",
    r" \  /| |_) | |   | | | || |  | | |  _| | |_) |",
    r" /  \|  __/| |___| |_| || |  | | | |___|  _ < ",
    r"/_/\_\_|   |_____|\___/|___| |_| |_____|_| \_|",
]

TAGLINE      = "[ UNAUTHORIZED ACCESS DETECTED // SYSTEM COMPROMISED ]"
GLITCH_CHARS = list("!@#$%^&*<>?/|\\[]{}~`\u2591\u2592\u2593\u2588\u2584\u2580\u25a0\u25a1\u25aa\u25ab")


def _supports_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _glitch_line(line: str, intensity: float = 0.07) -> str:
    """Replace random non-space characters with glitch symbols."""
    out = []
    for ch in line:
        if ch != " " and random.random() < intensity:
            out.append(random.choice(GLITCH_CHARS))
        else:
            out.append(ch)
    return "".join(out)


def _hex_noise(length: int = 72) -> str:
    """Generate exactly `length` hex characters for border decoration."""
    chunks = [f"{random.randint(0, 0xFFFF):04X}" for _ in range(length // 5 + 1)]
    return GRAY + DIM + " ".join(chunks)[:length] + RESET


def _print_glitch_frame(lines: list, color: str, passes: int = 3, delay: float = 0.18):
    """Overwrite the last N lines with glitched variants for corruption effect."""
    for _ in range(passes):
        sys.stdout.write(f"\033[{len(lines)}A")
        for line in lines:
            glitched = _glitch_line(line, intensity=0.12)
            sys.stdout.write("\r" + color + BOLD + glitched + RESET + "\n")
        sys.stdout.flush()
        time.sleep(delay)


def print_shodan_logo(
    animated: bool = True,
    color_scheme: str = "red",
    glitch: bool = True,
) -> None:
    """Render the Shodan Xploiter ASCII logo with optional animation and glitch FX."""
    use_color = _supports_color()

    palette = {
        "red":   (RED,   YELLOW, WHITE),
        "green": (GREEN, CYAN,   WHITE),
        "cyan":  (CYAN,  GREEN,  WHITE),
    }.get(color_scheme, (RED, YELLOW, WHITE))

    primary, accent, light = palette if use_color else ("", "", "")
    _r     = RESET if use_color else ""
    _b     = BOLD  if use_color else ""
    _d     = DIM   if use_color else ""
    _g     = GRAY  if use_color else ""
    _blink = BLINK if use_color else ""

    width = 72

    def w(text=""):
        print(text)

    def slow_print(text, delay=0.015):
        if animated:
            for ch in text:
                sys.stdout.write(ch)
                sys.stdout.flush()
                time.sleep(delay)
            print()
        else:
            print(text)

    w()
    if animated:
        slow_print(_g + _d + "  >> INITIALIZING SHODAN XPLOITER..." + _r, delay=0.018)
        time.sleep(0.2)
        slow_print(_g + _d + "  >> BYPASSING FIREWALL LAYER 3..."   + _r, delay=0.014)
        time.sleep(0.15)
        slow_print(_g + _d + "  >> ROOT ACCESS GRANTED"              + _r, delay=0.018)
        time.sleep(0.3)
    w()

    w(primary + _b + "\u2554" + "\u2550" * width + "\u2557" + _r)
    w(primary + "\u2551 " + _hex_noise(width - 2) + primary + " \u2551" + _r)
    w(primary + "\u2551" + " " * width + "\u2551" + _r)

    for line in LOGO_LINES:
        padded = line.center(width)
        print(primary + "\u2551" + _b + primary + padded + _r + primary + "\u2551" + _r)

    if animated and glitch:
        _print_glitch_frame(
            [ln.center(width) for ln in LOGO_LINES],
            primary, passes=3, delay=0.18
        )
        sys.stdout.write(f"\033[{len(LOGO_LINES)}A")
        for line in LOGO_LINES:
            padded = line.center(width)
            sys.stdout.write(primary + "\u2551" + _b + primary + padded + _r + primary + "\u2551" + _r + "\n")
        sys.stdout.flush()

    w(primary + "\u2560" + "\u2550" * width + "\u2563" + _r)

    for line in XPLOITER_LINES:
        padded = line.center(width)
        print(primary + "\u2551" + _b + accent + padded + _r + primary + "\u2551" + _r)

    if animated and glitch:
        _print_glitch_frame(
            [ln.center(width) for ln in XPLOITER_LINES],
            accent, passes=3, delay=0.18
        )
        sys.stdout.write(f"\033[{len(XPLOITER_LINES)}A")
        for line in XPLOITER_LINES:
            padded = line.center(width)
            sys.stdout.write(primary + "\u2551" + _b + accent + padded + _r + primary + "\u2551" + _r + "\n")
        sys.stdout.flush()

    w(primary + "\u2551" + " " * width + "\u2551" + _r)
    tagline_padded = TAGLINE.center(width)
    w(primary + "\u2551" + _blink + light + _b + tagline_padded + _r + primary + "\u2551" + _r)
    w(primary + "\u2551" + " " * width + "\u2551" + _r)
    w(primary + "\u2551 " + _hex_noise(width - 2) + primary + " \u2551" + _r)
    w(primary + "\u255a" + "\u2550" * width + "\u255d" + _r)

    w()
    meta = [
        ("VERSION",  "v1.0"),
        ("AUTHOR",   "Quantum Capital -- www.quantumcapital.capital"),
        ("STATUS",   "ARMED & READY"),
    ]
    for key, val in meta:
        if animated:
            slow_print(
                f"  {_g}{key:<10}{_r}{primary}{_b}{val}{_r}",
                delay=0.008
            )
        else:
            w(f"  {_g}{key:<10}{_r}{primary}{_b}{val}{_r}")
    w()


# -----------------------------------------------------------------------------
# Interactive IP input  [ADDED]
# Replaces the --ip argparse argument. Shown after the logo, before banner().
# -----------------------------------------------------------------------------

def prompt_for_ip() -> str:
    """
    Ask the user interactively for the target IP address.
    Validates IPv4 format (four octets, each 0-255).
    Loops until a valid address is entered.
    """
    _r  = RESET if _supports_color() else ""
    _b  = BOLD  if _supports_color() else ""
    red = RED   if _supports_color() else ""

    while True:
        try:
            raw = input(f"  {_b}Enter target IP address:{_r} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)

        parts = raw.split(".")
        try:
            if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts):
                print()
                return raw
        except ValueError:
            pass

        print(f"  {red}[!] Invalid IP address -- please enter a valid IPv4 address.{_r}")


# -----------------------------------------------------------------------------
# UI helpers
# -----------------------------------------------------------------------------

def banner(ip: str):
  
    console.print()
    title  = "[bold white]SHODAN XPLOITER v1.0[/bold white]"
    author = "[dim]by Quantum Capital -- www.quantumcapital.capital[/dim]"
    sub    = (
        f"[dim]Target: [cyan bold]{ip}[/cyan bold]  "
        f"Started: [yellow]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/yellow][/dim]"
    )
    console.print(Panel.fit(title + "\n" + author + "\n" + sub, border_style="cyan"))
    console.print()


def section(title: str, icon: str = "\u25ba"):
    console.print()
    console.print(Rule(f"[bold cyan]{icon} {title}[/bold cyan]", style="cyan"))


def ok(msg: str):
    console.print(f" [bold green]\u2713[/bold green] {msg}")


def warn(msg: str):
    console.print(f" [bold yellow]\u26a0[/bold yellow] [yellow]{msg}[/yellow]")


def info(msg: str):
    console.print(f" [dim]\u2192[/dim] [dim]{msg}[/dim]")


def field(label: str, value):
    v = str(value).strip() if value is not None else ""
    if v and v not in ("None", "null", "{}", "[]", ""):
        console.print(f" [bold white]{label}:[/bold white] [cyan]{v}[/cyan]")
    else:
        console.print(f" [bold white]{label}:[/bold white] [dim]n/a[/dim]")


def err(msg: str):
    console.print(f" [bold red]\u2717[/bold red] [red]{msg}[/red]")


# -----------------------------------------------------------------------------
# Spinner thread
# -----------------------------------------------------------------------------

def spinner_task(label: str, stop_event: threading.Event):
    frames = ["\u280b", "\u2819", "\u2839", "\u2838", "\u283c", "\u2834", "\u2826", "\u2827", "\u2807", "\u280f"]
    i = 0
    while not stop_event.is_set():
        frame = frames[i % len(frames)]
        console.print(f" [cyan]{frame}[/cyan] [dim]{label}...[/dim]", end="\r")
        time.sleep(0.1)
        i += 1
    console.print(" " * 60, end="\r")


# -----------------------------------------------------------------------------
# Collectors
# -----------------------------------------------------------------------------

def run_whois(ip: str) -> dict:
    section("WHOIS / RDAP", "\U0001f50d")
    info(f"Querying WHOIS/RDAP for {ip}...")
    t0 = time.time()
    result = whois_collector.collect(ip)
    elapsed = time.time() - t0

    if result["error"]:
        err(f"WHOIS failed: {result['error']}")
    else:
        ok(f"WHOIS/RDAP completed in {elapsed:.1f}s")
        d = result["data"]
        field("ASN",      str(d.get("asn")) + " -- " + str(d.get("asn_description", "")))
        field("CIDR",     d.get("asn_cidr"))
        field("Country",  d.get("asn_country_code"))
        field("Registry", d.get("asn_registry"))
        net = d.get("network", {})
        field("Net Name",  net.get("name"))
        field("IP Range",  str(net.get("start_address", "")) + " -> " + str(net.get("end_address", "")))
        field("Net Type",  net.get("type"))
        abuse_emails = []
        for obj in (d.get("objects") or {}).values():
            emails = obj.get("contact", {}).get("email") or []
            for e in emails:
                abuse_emails.append(e.get("value", "") if isinstance(e, dict) else str(e))
        if abuse_emails:
            field("Abuse email", ", ".join(abuse_emails[:3]))
    return result


def run_ipinfo(ip: str) -> dict:
    section("IPINFO.IO", "\U0001f30d")
    token_status = "set" if config.IPINFO_TOKEN else "free tier (no token)"
    info(f"Querying IPInfo.io for {ip} -- token: {token_status}")
    t0 = time.time()
    result = ipinfo_collector.collect(ip, config.IPINFO_TOKEN)
    elapsed = time.time() - t0

    if result["error"]:
        err(f"IPInfo failed: {result['error']}")
    else:
        ok(f"IPInfo completed in {elapsed:.1f}s")
        d = result["data"]
        field("Hostname",    d.get("hostname"))
        field("Location",    f"{d.get('city')}, {d.get('region')}, {d.get('country')}")
        field("Coordinates", d.get("loc"))
        field("Timezone",    d.get("timezone"))
        field("Org / ASN",   d.get("org"))
        field("Anycast",     d.get("anycast"))
        priv = d.get("privacy") or {}
        if priv:
            flags = [k for k, v in priv.items() if v is True]
            field("Privacy flags", ", ".join(flags) if flags else "none detected")
        abuse = d.get("abuse") or {}
        if abuse.get("email"):
            field("Abuse contact", abuse.get("email"))
    return result


def run_shodan(ip: str) -> dict:
    section("SHODAN", "\U0001f4e1")

    using_key = bool(config.SHODAN_API_KEY)
    if using_key:
        info(f"Querying Shodan API for {ip} (no credit cost)...")
    else:
        info("No SHODAN_API_KEY -- using passive web scraper directly...")

    t0 = time.time()
    result = shodan_collector.collect(ip, config.SHODAN_API_KEY)
    elapsed = time.time() - t0

    is_fallback = result.get("fallback", False)

    if is_fallback:
        api_err = result.get("api_error", "")
        if api_err and using_key:
            warn(f"Shodan API failed ({api_err}) -- switched to passive web scraper")
        else:
            warn("Using passive web scraper (no API key)")

    if result["error"]:
        err(f"Shodan failed: {result['error']}")
    else:
        method_label = "[yellow]web scraper[/yellow]" if is_fallback else "[green]API[/green]"
        ok(f"Shodan completed in {elapsed:.1f}s [dim](source: {method_label}[/dim])")

        d     = result["data"]
        ports = d.get("ports", [])
        svcs  = d.get("services", [])
        vulns_all = []
        for s in svcs:
            vulns_all.extend(s.get("vulns", []))

        field("Organization", d.get("org"))
        field("ISP",          d.get("isp"))
        field("ASN",          d.get("asn"))
        field("Country",      d.get("country_name"))
        field("City",         d.get("city"))
        field("OS",           d.get("os"))
        field("Hostnames",    ", ".join(d.get("hostnames", [])) or "none")
        field("Tags",         ", ".join(d.get("tags", [])) or "none")
        field("Last update",  d.get("last_update"))
        console.print(f" [bold white]Open ports:[/bold white] [bold cyan]{sorted(ports)}[/bold cyan]")

        if svcs:
            console.print()
            console.print(" [bold white]Services detail:[/bold white]")
            t = Table(
                box=box.SIMPLE, show_header=True, header_style="bold magenta",
                padding=(0, 1), show_edge=False,
            )
            t.add_column("Port",           style="cyan",  no_wrap=True)
            t.add_column("Proto",          style="dim",   no_wrap=True)
            t.add_column("Product",        style="white")
            t.add_column("Version",        style="yellow")
            t.add_column("CVEs",           style="red")
            t.add_column("Banner snippet", style="dim",   max_width=40)
            for s in svcs:
                cve_list    = s.get("vulns", [])
                banner_snip = (s.get("banner") or "").replace("\n", " ")[:40]
                t.add_row(
                    str(s.get("port", "")),
                    s.get("transport", "tcp"),
                    s.get("product") or "unknown",
                    s.get("version") or "-",
                    ", ".join(cve_list) if cve_list else "-",
                    banner_snip or "-",
                )
            console.print(t)

        if vulns_all:
            unique_vulns = list(set(vulns_all))
            console.print(f" [bold red]Total CVEs detected: {len(unique_vulns)}[/bold red]")
            for v in unique_vulns[:5]:
                console.print(f" [red]\u2022 {v}[/red]")
            if len(unique_vulns) > 5:
                console.print(f" [dim]... and {len(unique_vulns) - 5} more[/dim]")

        if is_fallback:
            all_cves = d.get("all_cves_found", [])
            if all_cves:
                console.print(
                    f" [bold red]CVEs found in page (scraper):[/bold red] "
                    f"[red]{', '.join(all_cves[:8])}[/red]"
                )

    return result




# -----------------------------------------------------------------------------
# AI call wrapper -- streaming with complete() fallback.
# sys.stdout.write() is used instead of console.print() for real-time output
# because Rich buffers internally and does not flush on each token.
#
#           uses HAIKU_MODEL and Phases 2-3 use SONNET_MODEL.
# -----------------------------------------------------------------------------

def run_ai_phase(
    label: str,
    provider,
    system_p: str,
    user_p: str,
    max_tokens: int,
    model: str,
) -> str:
    info(f"Provider: [bold]{provider.provider_name}[/bold] / [cyan]{model}[/cyan]")
    info(f"Prompt size: ~{len(user_p) // 4} tokens (estimated) | max_tokens: {max_tokens}")

    t0 = time.time()

    if hasattr(provider, "stream"):
        console.print(f" [dim]\u2192[/dim] [dim]Streaming {label}...[/dim]")
        console.print()
        chunks = []
        try:
            for chunk in provider.stream(system_p, user_p, max_tokens, model=model):
                sys.stdout.write(chunk)
                sys.stdout.flush()
                chunks.append(chunk)
            sys.stdout.write("\n\n")
            sys.stdout.flush()
            console.file.flush()
            response = "".join(chunks)
        except Exception as e:
            err(f"Streaming failed ({e}), falling back to complete()...")
            response = provider.complete(system_p, user_p, max_tokens, model=model)
            console.print(response)
    else:
        stop = threading.Event()
        t = threading.Thread(target=spinner_task, args=(label, stop), daemon=True)
        t.start()
        try:
            response = provider.complete(system_p, user_p, max_tokens, model=model)
        except Exception as e:
            stop.set()
            t.join()
            err(f"AI call failed: {e}")
            raise
        stop.set()
        t.join()
        console.print(response)

    elapsed    = time.time() - t0
    out_tokens = len(response) // 4
    ok(f"{label} completed in {elapsed:.1f}s (~{out_tokens} tokens output)")
    return response


# -----------------------------------------------------------------------------
# Three-phase analysis
#
# Phase 1 -- Identity & Attribution    max_tokens: 2500   model: HAIKU_MODEL
# Phase 2 -- Attack Surface & Vulns    max_tokens: 8096   model: SONNET_MODEL
# Phase 3 -- Penetration Testing Guide max_tokens: 16000  model: SONNET_MODEL
#
#           (not found in Shodan index), pipeline stops here and returns
#           placeholder strings for phase2 and phase3 -- no point analysing
#           an attack surface that does not exist in the dataset.
#
# [UNCHANGED] Phase 3 logic, has_surface check, rate-limit pauses -- all intact.
# -----------------------------------------------------------------------------

def run_analysis(ip: str, raw: dict, no_ai: bool) -> Tuple[str, str, str]:
    if no_ai:
        warn("AI analysis skipped (--no-ai flag)")
        return ("(AI skipped)", "(AI skipped)", "(AI skipped)")

    provider = get_provider()
    delay    = config.AI_PHASE_DELAY.get("claude", 3)

    # ── PHASE 1 -- Identity & Attribution ────────────────────────────────────
    section("AI PHASE 1 -- Identity & Attribution", "\U0001f916")
    info("Building Phase 1 prompt from WHOIS + IPInfo data...")
    p1_prompt = prompts.phase1_prompt(ip, raw["whois"]["data"], raw["ipinfo"]["data"])
    info(f"Prompt ready -- {len(p1_prompt)} chars / ~{len(p1_prompt) // 4} tokens")

    phase1 = run_ai_phase(
        "Phase 1 -- Identity",
        provider,
        prompts.SYSTEM_PROMPT,
        p1_prompt,
        max_tokens=2500,
        model=HAIKU_MODEL,      # lightweight model -- attribution only, no deep reasoning needed
    )
    section("IDENTITY REPORT", "\U0001f916")

    # Skip Phase 2/3 if Shodan has no data for this IP.
    shodan_data    = raw["shodan"].get("data", {})
    shodan_indexed = bool(
        not raw["shodan"].get("error") and
        (shodan_data.get("ports") or shodan_data.get("services"))
    )
    if not shodan_indexed:
        warn(
            "IP not found in Shodan index -- "
            "Phase 2 and Phase 3 skipped (no attack surface data available)."
        )
        return phase1, "(skipped -- IP not found in Shodan)", "(skipped -- IP not found in Shodan)"

    # ── Rate-limit pause before Phase 2 ──────────────────────────────────────
    if delay > 0:
        console.print()
        info(f"Rate limit pause: [yellow]{delay}s[/yellow] before Phase 2...")
        for remaining in range(delay, 0, -1):
            console.print(f" [dim] {remaining:3d}s remaining...[/dim]", end="\r")
            time.sleep(1)
        console.print(" " * 40, end="\r")

    # ── PHASE 2 -- Attack Surface & Vulnerabilities ───────────────────────────
    section("AI PHASE 2 -- Attack Surface & Vulnerabilities", "\U0001f534")
    info("Building Phase 2 prompt from Shodan + Phase 1 context...")

    p2_prompt = prompts.phase2_prompt(ip, raw["shodan"], {}, phase1)
    info(f"Prompt ready -- {len(p2_prompt)} chars / ~{len(p2_prompt) // 4} tokens")

    phase2 = run_ai_phase(
        "Phase 2 -- Vulnerabilities",
        provider,
        prompts.SYSTEM_PROMPT,
        p2_prompt,
        max_tokens=16000,
        model=SONNET_MODEL,     # full reasoning for vulnerability analysis
    )
    section("VULNERABILITY REPORT", "\U0001f534")

    # ── Phase 3 gate -- unchanged from original ───────────────────────────────
    has_surface = bool(
        raw.get("shodan", {}).get("data", {}).get("ports") or
        raw.get("shodan", {}).get("data", {}).get("services")
    )

    if not has_surface:
        warn("Phase 3 skipped -- no service data available")
        phase3 = "(Phase 3 skipped -- no service data available)"
        return phase1, phase2, phase3

    if delay > 0:
        console.print()
        info(f"Rate limit pause: [yellow]{delay}s[/yellow] before Phase 3...")
        for remaining in range(delay, 0, -1):
            console.print(f" [dim] {remaining:3d}s remaining...[/dim]", end="\r")
            time.sleep(1)
        console.print(" " * 40, end="\r")

    # ── PHASE 3 -- Penetration Testing Guide ─────────────────────────────────
    section("AI PHASE 3 -- Penetration Testing Guide", "\U0001f513")
    info("Building Phase 3 prompt from Phase 1 + Phase 2 summaries...")
    p3_prompt = prompts.phase3_prompt(ip, phase1, phase2)
    info(f"Prompt ready -- {len(p3_prompt)} chars / ~{len(p3_prompt) // 4} tokens")

    phase3 = run_ai_phase(
        "Phase 3 -- Pentest Guide",
        provider,
        prompts.SYSTEM_PROMPT,
        p3_prompt,
        max_tokens=16000,
        model=SONNET_MODEL,     # maximum output -- full pentest guide
    )
    section("PENETRATION TESTING GUIDE", "\U0001f513")

    return phase1, phase2, phase3


# -----------------------------------------------------------------------------
# Entry point
#
# -----------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Shodan Xploiter v1.0 -- OSINT IP analysis by Quantum Capital"
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Run collectors only, skip AI analysis, print raw JSON",
    )
    parser.add_argument(
        "--output-dir",
        default=config.OUTPUT_DIR,
        help="Directory for saved reports (default: ./reports)",
    )
    args = parser.parse_args()

    # Show logo first, then ask for target IP interactively
    print_shodan_logo(animated=True, color_scheme="red", glitch=True)
    target_ip = prompt_for_ip()

    banner(target_ip)

    info(f"AI provider:     [bold]Anthropic Claude[/bold]")
    info(f"Phase 1 model:   [cyan]{HAIKU_MODEL}[/cyan]")
    info(f"Phase 2+3 model: [cyan]{SONNET_MODEL}[/cyan]")
    info(f"AI analysis:     {'[yellow]OFF[/yellow]' if args.no_ai else '[green]ON[/green]'}")
    info(f"Output dir:      {args.output_dir}")

    t_total = time.time()
    raw = {}
    raw["whois"]  = run_whois(target_ip)
    raw["ipinfo"] = run_ipinfo(target_ip)
    raw["shodan"] = run_shodan(target_ip)

    # ── Collection summary ────────────────────────────────────────────────────
    section("COLLECTION SUMMARY", "\U0001f4cb")
    tbl = Table(
        box=box.SIMPLE, show_header=True, header_style="bold white",
        padding=(0, 2), show_edge=False,
    )
    tbl.add_column("Collector", style="bold")
    tbl.add_column("Status")
    tbl.add_column("Method", style="dim")

  
    for name, key in [("WHOIS", "whois"), ("IPInfo", "ipinfo"), ("Shodan", "shodan")]:
        e      = raw[key]["error"]
        method = raw[key].get("source_method", "")
        method_label = (
            "[yellow]web scraper[/yellow]" if method == "web_scraper"
            else f"[green]{method}[/green]" if method
            else ""
        )
        if not e:
            tbl.add_row(name, "[green]\u2713 OK[/green]", method_label)
        else:
            tbl.add_row(name, f"[yellow]\u26a0 {e}[/yellow]", method_label)
    console.print(tbl)

    phase1, phase2, phase3 = run_analysis(target_ip, raw, args.no_ai)

    if not args.no_ai:
        section("SAVING REPORT", "\U0001f4be")
        info("Writing Markdown + JSON reports...")
        files = report_writer.write(
            ip=target_ip,
            phase1=phase1,
            phase2=phase2,
            phase3=phase3,
            raw_data=raw,
            output_dir=args.output_dir,
            provider="claude",
            model=SONNET_MODEL,
        )
        ok(f"OSINT Report  -> [bold]{files['markdown']}[/bold]")
        ok(f"Pentest Guide -> [bold]{files['pentest']}[/bold]")
        ok(f"JSON raw      -> [bold]{files['json']}[/bold]")
        total = time.time() - t_total
        console.print()
        done_msg = "[bold green]Analysis complete![/bold green]"
        time_msg = (
            f"[dim]Total time: [yellow]{total:.1f}s[/yellow]  "
            f"Report: [cyan]{files['markdown']}[/cyan][/dim]"
        )
        console.print(Panel.fit(done_msg + "\n" + time_msg, border_style="green"))
        console.print(
            "\n [dim]Shodan Xploiter v1.0 -- "
            "Quantum Capital (www.quantumcapital.capital)[/dim]\n"
        )
    else:
        section("RAW DATA (--no-ai mode)", "\U0001f4c4")
        console.print_json(json.dumps(raw, default=str))


if __name__ == "__main__":
    main()
