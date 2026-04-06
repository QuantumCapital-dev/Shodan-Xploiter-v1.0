"""
Configuration for Shodan Xploiter v1.0.
Loads all settings from .env in the same directory as this file.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).parent / ".env", override=True)

# ── Anthropic (sole AI provider) ──────────────────────────────
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

# ── Data collectors ───────────────────────────────────────────
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
IPINFO_TOKEN   = os.getenv("IPINFO_TOKEN", "")

# Strip placeholder values left over from .env.example
_PLACEHOLDERS = {"your_shodan_api_key_here", "your_anthropic_api_key_here"}
if SHODAN_API_KEY in _PLACEHOLDERS:
    SHODAN_API_KEY = ""

# ── Rate-limit pause between AI phases (seconds) ──────────────
# Anthropic Sonnet has generous rate limits; 2s is sufficient.
AI_PHASE_DELAY = int(os.getenv("AI_PHASE_DELAY", "2"))

# ── Report output directory ───────────────────────────────────
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "./reports")
