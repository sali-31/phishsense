#!/usr/bin/env python3
"""
PhishSense - Simple phishing URL & email risk scorer.

This script lets you:
- Analyze a single URL for phishing indicators.
- Analyze an email text file for phishing indicators.
- Output results in either human-readable text or JSON.

Usage examples (from Terminal):
    python phishsense.py --url "http://example.com/login"
    python phishsense.py --email-file suspicious_mail.txt
    python phishsense.py --url "http://example.com/login" --format json
"""

import argparse          # For parsing command-line arguments like --url and --email-file
import json              # For producing JSON output when requested
import re                # For regular expressions (pattern matching)
import string            # For working with sets of characters
from dataclasses import dataclass   # To define a simple data structure (RuleResult)
from typing import List, Tuple, Dict
from urllib.parse import urlparse   # To break a URL into parts (scheme, host, path, etc.)

import tldextract        # Third-party library to nicely split domains into subdomain/domain/tld


# ---------------------------
# Data structure for rule hits
# ---------------------------

@dataclass
class RuleResult:
    """
    Represents one rule that was triggered during analysis.

    Attributes:
        name: Short identifier for the rule.
        score: How many "risk points" this rule contributes.
        reason: Human-readable explanation of why it triggered.
    """
    name: str
    score: int
    reason: str


# ---------------- URL ANALYSIS ---------------- #

# List of TLDs (top-level domains) that are often associated with abuse.
# This is NOT a definitive list, just examples for educational purposes.
SUSPICIOUS_TLDS = {
    "zip", "xyz", "top", "kim", "ru", "cn", "tk", "ga", "ml", "gq"
}

# Keywords that often appear in phishing paths like /login, /verify, /update, etc.
SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "update", "secure", "reset",
    "paypal", "bank", "office365", "microsoft", "appleid",
}


def shannon_entropy(s: str) -> float:
    """
    Calculate the Shannon entropy of a string.

    Higher entropy means the string is more "random-looking".
    Phishing URLs sometimes have random tokens in query parameters.

    Example:
        "aaaaaa" -> low entropy
        "Aj2k91Xz" -> higher entropy
    """
    if not s:
        return 0.0

    from math import log2

    # Count how many times each character appears
    counts: Dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1

    entropy = 0.0
    length = len(s)

    # Shannon entropy formula: sum( -p * log2(p) ) over all characters
    for c in counts.values():
        p = c / length
        entropy -= p * log2(p)

    return entropy


def analyze_url(url: str) -> Tuple[int, List[RuleResult]]:
    """
    Analyze a URL string and return a risk score (0-100)
    plus a list of triggered RuleResult objects.
    """
    # Ensure the URL has a scheme (http:// or https://), or urlparse treats it oddly.
    parsed = urlparse(url if "://" in url else "http://" + url)

    # tldextract splits the host (netloc) into three parts:
    #   subdomain, domain, suffix (TLD)
    ext = tldextract.extract(parsed.netloc)
    domain = ".".join(part for part in [ext.domain, ext.suffix] if part)
    subdomain = ext.subdomain or ""

    rules: List[RuleResult] = []
    score = 0

    # Rule 1: IP address instead of domain
    # Example: http://192.168.0.10/login
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", parsed.hostname or ""):
        rules.append(RuleResult(
            "ip_host",
            20,
            "URL uses a raw IP address instead of a domain name."
        ))
        score += 20

    # Rule 2: Punycode (IDN) in hostname, e.g. xn--paypal-secure-abc.com
    # These can be used in homograph attacks.
    if parsed.hostname and "xn--" in parsed.hostname:
        rules.append(RuleResult(
            "punycode",
            15,
            "Hostname contains punycode (IDN), which is sometimes used in homograph attacks."
        ))
        score += 15

    # Rule 3: Suspicious TLD
    # For example: .xyz, .top, .ru, etc.
    if ext.suffix:
        tld = ext.suffix.split(".")[-1]  # handle multi-part TLDs like "co.uk"
        if tld in SUSPICIOUS_TLDS:
            rules.append(RuleResult(
                "suspicious_tld",
                10,
                f"TLD '.{tld}' is frequently associated with abuse (in this educational example)."
            ))
            score += 10

    # Rule 4: Many subdomains, e.g. login.security.paypal.com.account.verify.example.com
    if subdomain and subdomain.count(".") >= 2:
        rules.append(RuleResult(
            "many_subdomains",
            10,
            f"Hostname has many subdomains ('{subdomain}'), a pattern sometimes seen in phishing."
        ))
        score += 10

    # Rule 5: '@' in URL
    # Historically used to confuse users about the real host (everything before @ is user info).
    if "@" in parsed.netloc or "@" in parsed.path:
        rules.append(RuleResult(
            "at_symbol",
            15,
            "URL contains '@', which can obscure the real destination host."
        ))
        score += 15

    # Rule 6: Very long URL
    full_url = url
    if len(full_url) > 100:
        rules.append(RuleResult(
            "long_url",
            5,
            f"URL length is {len(full_url)} characters (unusually long)."
        ))
        score += 5

    # Rule 7: Suspicious keywords in the path (e.g. /login, /verify, /secure)
    lowered_path = parsed.path.lower()
    matched_keywords = {kw for kw in SUSPICIOUS_KEYWORDS if kw in lowered_path}
    if matched_keywords:
        rules.append(RuleResult(
            "suspicious_keywords",
            10,
            f"Path contains sensitive keywords: {', '.join(sorted(matched_keywords))}."
        ))
        score += 10

    # Rule 8: High entropy query string (random-looking parameters)
    query = parsed.query
    if query:
        # Remove separators like & and = so we measure only the core characters
        filtered = "".join(
            ch for ch in query
            if ch not in "&=/%" and ch in string.printable
        )
        ent = shannon_entropy(filtered)
        # Threshold chosen just for demonstration; 4.0 is "kind of random"
        if ent > 4.0 and len(filtered) > 20:
            rules.append(RuleResult(
                "high_entropy_query",
                10,
                f"Query parameters look random (entropy={ent:.2f}); sometimes used to hide tokens or payloads."
            ))
            score += 10

    # Keep score in the 0-100 range
    score = max(0, min(100, score))
    return score, rules


# ---------------- EMAIL ANALYSIS ---------------- #

# Patterns that represent urgent or threatening language.
EMAIL_URGENCY_PATTERNS = [
    r"urgent action required",
    r"your account will be (?:closed|suspended|locked)",
    r"verify your account",
    r"update your (?:information|details)",
    r"immediately",
]

# Generic greetings often seen in phishing emails.
EMAIL_GENERIC_GREETING = [
    r"dear customer",
    r"dear user",
    r"valued customer",
]


def analyze_email(text: str) -> Tuple[int, List[RuleResult]]:
    """
    Analyze email text (as a string) and return a risk score plus rule hits.
    """
    lower = text.lower()
    rules: List[RuleResult] = []
    score = 0

    # Rule 1: Urgency phrases
    for pattern in EMAIL_URGENCY_PATTERNS:
        if re.search(pattern, lower):
            rules.append(RuleResult(
                "urgency_language",
                15,
                f"Contains urgency phrase matching: '{pattern}'."
            ))
            score += 15
            break  # We add it only once even if multiple patterns match

    # Rule 2: Generic greeting
    for pattern in EMAIL_GENERIC_GREETING:
        if re.search(pattern, lower):
            rules.append(RuleResult(
                "generic_greeting",
                10,
                f"Uses generic greeting matching: '{pattern}'."
            ))
            score += 10
            break

    # Rule 3: Request for credentials
    if re.search(r"(confirm|enter|send)\s+(your\s+)?(password|credentials|login)", lower):
        rules.append(RuleResult(
            "credentials_request",
            20,
            "Appears to request credentials or password."
        ))
        score += 20

    # Rule 4: Many exclamation marks
    exclamations = lower.count("!")
    if exclamations >= 5:
        rules.append(RuleResult(
            "many_exclamations",
            5,
            f"Contains {exclamations} exclamation marks."
        ))
        score += 5

    # Rule 5: High ratio of ALL CAPS words (e.g. "URGENT", "WARNING")
    words = re.findall(r"\b\w+\b", text)
    if words:
        caps_words = [w for w in words if len(w) > 3 and w.isupper()]
        if len(caps_words) / len(words) > 0.1:
            rules.append(RuleResult(
                "many_caps_words",
                5,
                "Contains a high proportion of ALL CAPS words."
            ))
            score += 5

    # Normalize to 0-100
    score = max(0, min(100, score))
    return score, rules


# ---------------- OUTPUT / CLI ---------------- #

def risk_level(score: int) -> str:
    """
    Convert a numeric score into a simple textual level.
    """
    if score >= 70:
        return "HIGH RISK"
    elif score >= 40:
        return "MEDIUM RISK"
    else:
        return "LOW RISK"


def print_report(kind: str, score: int, rules: List[RuleResult], output_format: str) -> None:
    """
    Print the analysis results to the terminal.

    kind: "URL" or "EMAIL"
    score: final risk score
    rules: list of RuleResult objects that were triggered
    output_format: "text" or "json"
    """
    level = risk_level(score)

    if output_format == "json":
        # Build a Python dict that can be converted to JSON.
        data = {
            "type": kind,
            "score": score,
            "level": level,
            "rules": [
                {
                    "name": r.name,
                    "score": r.score,
                    "reason": r.reason,
                }
                for r in rules
            ],
            "note": "Heuristic, educational tool. Manual review is required."
        }
        # Print nicely formatted JSON so it's readable or can be piped into jq, etc.
        print(json.dumps(data, indent=2))
        return

    # Default: human-readable text output
    print(f"\nAnalysis type: {kind}")
    print(f"Risk score: {score}/100  ->  {level}")
    print("\nTriggered rules:")

    if not rules:
        print("  (none – nothing suspicious detected by current heuristics)")
    else:
        for r in rules:
            print(f"  - [{r.score} pts] {r.name}: {r.reason}")

    print("\nNote: This is a heuristic, educational tool. Manual review is required.")


def parse_args() -> argparse.Namespace:
    """
    Set up and parse command-line arguments.

    We use a mutually exclusive group so the user must choose
    either --url OR --email-file, not both.
    """
    parser = argparse.ArgumentParser(
        description="PhishSense - Simple phishing URL & email risk scorer."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", help="URL to analyze (e.g., http://example.com/login).")
    group.add_argument("--email-file", help="Path to a text file containing email content.")

    # New option: choose output format (text or json)
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (text or json). Default is text."
    )

    return parser.parse_args()


def main() -> None:
    """
    Main entry point:
    - Parse arguments.
    - Call the right analysis function.
    - Print a report in the chosen format.
    """
    args = parse_args()

    # Use the selected output format
    output_format = args.format

    if args.url:
        score, rules = analyze_url(args.url)
        print_report("URL", score, rules, output_format)

    elif args.email_file:
        # Read the entire email text file into a string
        with open(args.email_file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        score, rules = analyze_email(content)
        print_report("EMAIL", score, rules, output_format)


# Standard Python pattern: only run main() if this file is executed directly.
if __name__ == "__main__":
    main()
