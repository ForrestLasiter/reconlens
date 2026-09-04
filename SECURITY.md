# Security & Responsible Use

## Authorized use only

ReconLens is a **defensive** tool for monitoring the attack surface of systems
**you own or are explicitly authorized to test**. It performs active
reconnaissance — subdomain enumeration, port scanning, service probing, and
vulnerability template matching.

Running these techniques against systems you do not own or have written
permission to test may be **illegal** in your jurisdiction (e.g. the U.S.
Computer Fraud and Abuse Act, the UK Computer Misuse Act, and equivalents
elsewhere), regardless of intent.

ReconLens enforces an **allowlist** (`scope.yaml`): it refuses to scan any
target or discovered host that you have not explicitly listed. This is a
guardrail, not legal cover. **You** are solely responsible for ensuring you are
authorized to scan everything in your scope. Do not attempt to circumvent the
scope gate.

By using this software you agree that the authors bear no liability for how you
use it (see `LICENSE`).

## Reporting a vulnerability in ReconLens

If you find a security issue **in ReconLens itself** (e.g. a way to bypass the
scope gate, a command-injection path, or an SSRF), please report it privately:

- Open a **GitHub Security Advisory** via the repository's **Security → Report a
  vulnerability** tab, or
- Open a regular issue **only** if the problem is not sensitive.

Please do not disclose scope-bypass issues publicly before a fix is available —
they directly affect the tool's safety guarantees.

## Handling of scan data

ReconLens stores everything it discovers in a local SQLite database
(`data/reconlens.db`) on the host you run it on. Nothing is sent anywhere by
default. Treat that database as sensitive: it is a map of your own exposed
surface.
