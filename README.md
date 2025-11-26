# PhishSense – Phishing URL & Email Risk Scorer

PhishSense is a small, self-contained security tool that assigns a risk score
to URLs or email content based on simple, explainable phishing heuristics.

The goal of the project is to practice **adversarial thinking** and show how
common phishing techniques can be translated into concrete detection logic
that fits naturally into a security-aware software development workflow.

---

## Key Ideas

- Focus on **human-understandable rules**, not “magic” ML.
- Treat phishing as a combination of:
  - **Technical signals** (domains, TLDs, URL structure, entropy, etc.).
  - **Social-engineering signals** (urgency, generic greetings, credential requests).
- Provide **explainable output**:
  - A numeric risk score.
  - The exact rules that were triggered and why.
  - Optional JSON output for integration / automation.

---

## Features

### URL analysis

PhishSense inspects URLs for a variety of heuristic indicators:

- **IP-based hosts**  
  - e.g., `http://192.168.0.10/login` instead of a named domain.

- **Punycode / IDN hostnames**  
  - e.g., `xn--...` domains that can participate in homograph attacks.

- **Suspicious TLDs (example list only)**  
  - e.g., `.xyz`, `.top`, `.ru`, etc. – used here for educational purposes.

- **Excessive subdomains**  
  - Patterns like `login.security.paypal.com.account.verify.example.com`
    that may be used to visually confuse users.

- **`@` symbols in URLs**  
  - Historically used to hide the true destination host.

- **Sensitive keywords in paths**  
  - e.g., `login`, `verify`, `update`, `secure`, `paypal`, `bank`, etc.

- **High-entropy query strings**  
  - Random-looking tokens in query parameters, which can indicate opaque tracking
    or payload data.

Each triggered rule contributes to a **0–100 risk score** and is recorded with
a short explanation.

---

### Email analysis

PhishSense also scores plain-text email content for social-engineering signals:

- **Urgency and threat language**  
  - e.g., “urgent action required”, “your account will be suspended”, “immediately”.

- **Generic greetings**  
  - e.g., “Dear customer”, “Dear user”, “Valued customer”.

- **Explicit credential requests**  
  - e.g., asking the user to “confirm your password” or “send your login”.

- **Emotional formatting**  
  - Excessive exclamation marks.
  - High proportion of ALL CAPS words such as “URGENT” or “WARNING”.

Again, each heuristic contributes to a normalized **risk score** plus an
explanation of which rules fired.

---
Example use cases

Quick, explainable phishing demos in security discussions or study groups.

Practicing threat modeling: “What makes this URL/email suspicious?”

A starting point for integrating heuristic checks into a CI pipeline
(e.g., fail a build if high-risk URLs are committed).

---

Limitations & Scope

PhishSense is intentionally small and educational:

It is not a production-ready anti-phishing engine.

Rules are simplified and incomplete by design.

Results are heuristic estimates and must be combined with:

Organizational policies,

Additional technical controls,

Manual review by a human.

That said, the project is designed so that new rules, signals, and checks
can be added incrementally as part of an ongoing learning process.

---

## Output formats

PhishSense supports two output formats:

- **Text (default)** – human-readable CLI report.
- **JSON** – structured machine-readable result for integration into other tools.

Example JSON structure:

```json
{
  "type": "URL",
  "score": 72,
  "level": "HIGH RISK",
  "rules": [
    {
      "name": "suspicious_tld",
      "score": 10,
      "reason": "TLD '.xyz' is frequently associated with abuse (in this educational example)."
    }
  ],
  "note": "Heuristic, educational tool. Manual review is required."
}

