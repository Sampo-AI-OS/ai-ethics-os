# AI Ethics OS

AI Ethics OS is a FastAPI-based compliance assessment platform for EU AI Act use cases. This public edition is positioned as:

- a development support tool for building systems that stay inside those controls from the start
- a scoring-first showcase of a broader audit-oriented product direction

AI Ethics OS should be understood as a product created within Sampo AI OS, the broader autonomous digital office behind this portfolio. In practical terms, this means the application does not only return a score, but also reflects the product thinking, engineering discipline, and compliance-guidance orientation of the wider Sampo AI OS environment.

This portfolio copy is a curated public edition. See `PUBLIC_EDITION_SCOPE.md` for what is included here and what was intentionally left out of the original internal working project.

This repository is also intended to function as a public showcase for Sampo AI OS: a clear, reviewable product output from the digital office, not the full internal platform itself.

## Quick Evaluation Path

If you want to evaluate the project quickly as a portfolio piece, use this order:

1. Read the capability summary and compliance semantics in this README.
2. Open `demo.html` and run the public demo scenarios.
3. Review the screenshots in `media/screenshots/`.
4. Watch `media/video/frontend-demo.mp4` for a short guided walkthrough.
5. Inspect `services/ethics_scoring.py` and `services/certificate.py` for the core reasoning and audit logic.
6. Run `pytest tests -v` to validate the main regression coverage.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![JavaScript](https://img.shields.io/badge/JavaScript-ES2022-yellow)
![Docker](https://img.shields.io/badge/Docker-ready-blue)

## What This Application Does

The application has two core modes:

1. Rule-based compliance scoring
	 It evaluates a structured description of an AI system against a modeled subset of EU AI Act obligations and prohibited practices.

2. Evidence and certificate concepts
	 The broader product direction includes behavioral evidence auditing and verifiable certificates, but the full live audit runner is intentionally omitted from this public edition.

This means the public repository demonstrates the scoring product directly while showing only selected parts of the audit architecture.

In the broader Sampo AI OS framing, this repository is one product artifact from the office's solution inventory: public enough to evaluate and reuse, but intentionally curated rather than identical to the full internal production environment.

## Key Capabilities

- EU AI Act-style scoring for modeled Articles 5 and 9-15 controls
- prebuilt demo scenarios such as HR screening, credit scoring, and social scoring
- authenticated creation of custom rules
- authenticated scoring of custom AI system descriptions
- tamper-evident evidence-chain concepts
- certificate verification concepts
- English compliance guidance intended for both audit interpretation and development-time remediation

## Compliance Semantics

The score is not presented as a blanket ethical approval. Instead, the application returns:

- `risk_classification`: the classification produced by the modeled rules
- `violation_rules`: confirmed rule failures
- `remediation_hints`: concrete remediation steps
- `compliance_guidance`: interpretation text explaining what the result means, why it matters, and what boundary must not be crossed next

Important interpretation rules:

- `Prohibited` means the system crosses a prohibited line in the modeled rule set.
- `High-Risk - Non-Compliant` means the use case may still be in a legally assessable high-risk category, but the control set is materially insufficient.
- `High-Risk - Needs Review` means no prohibited practice was detected in the modeled checks, but important gaps remain.
- `High-Risk - Compliant` means the modeled controls appear satisfied. It does not mean the system is harmless, risk-free, or exempt from scrutiny.

## Architecture Overview

### Backend

- FastAPI application in `main.py`
- SQLAlchemy ORM models in `models/`
- PostgreSQL database configured in `database.py`
- scoring engine in `services/ethics_scoring.py`
- evidence chain and certificate services in `services/evidence_chain.py` and `services/certificate.py`
- redacted public placeholder for the internal scenario library in `models/test_scenario.py`

### Frontend

- standalone browser demo in `demo.html`
- React dashboard prototype in `pages/EthicsDashboard.js`

### Persistence and Integrity

- rules, users, and supporting data models are stored in PostgreSQL
- evidence blocks are linked by hash so post-hoc modification becomes detectable
- certificates include a deterministic SHA-256 fingerprint for offline verification

## Requirements

- Python 3.10 or newer
- Docker Desktop or equivalent Docker runtime
- Docker Compose support via `docker compose`

## Quick Start

### Docker

This is the recommended way to run the project.

```bash
docker compose up --build
```

Run in the background:

```bash
docker compose up -d
```

Stop the stack:

```bash
docker compose down
```

By default, the API is published on `http://localhost:18000`.

Swagger UI:

```text
http://localhost:18000/docs
```

Health check:

```text
http://localhost:18000/health
```

If port `18000` is already in use, override it without editing the compose file:

```powershell
$env:APP_PORT=18080
docker compose up --build
```

### Local Development

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the API in development mode:

```bash
uvicorn main:app --reload --port 18000
```

Run the API in production-style mode:

```bash
uvicorn main:app --host 0.0.0.0 --port 18000
```

## Authentication

The application supports authenticated user registration and login.

Available endpoints:

- `POST /auth/register`
- `POST /auth/login`

The login endpoint returns a Bearer token, which is required for:

- creating and deleting rules
- scoring custom systems through the protected scoring endpoint
- accessing protected endpoints that remain enabled in the public edition

### Registration Example

```json
{
	"email": "analyst@example.com",
	"password": "Secret123!",
	"full_name": "Example Analyst"
}
```

### Login Example

Use `application/x-www-form-urlencoded`:

```text
username=analyst@example.com&password=Secret123!
```

## Rule-Based Scoring

The protected scoring endpoint is:

- `POST /score`

The request body contains:

- `model_id`: display name or identifier for the assessed system
- `model_details`: a flat dictionary of control flags used by the scoring engine

### Example Request

```json
{
	"model_id": "Credit Decisioning API",
	"model_details": {
		"is_social_scoring": false,
		"is_realtime_biometric_public": false,
		"has_risk_management_system": true,
		"uses_demographic_features": false,
		"has_bias_testing": true,
		"has_technical_documentation": true,
		"logs_decisions": true,
		"has_explainability": true,
		"has_human_oversight": true,
		"has_accuracy_metrics": true
	}
}
```

### Example Response Shape

```json
{
	"model_id": "Credit Decisioning API",
	"total_possible": 100,
	"current_score": 86,
	"risk_classification": "High-Risk - Compliant",
	"compliance_guidance": "...",
	"analysis": "...",
	"violation_rules": [],
	"remediation_hints": [],
	"timestamp": "2026-04-05T09:05:14.610368"
}
```

`analysis` is currently retained as a compatibility alias of `compliance_guidance`.

## Demo Scenarios

Public demo routes are available without authentication.

- `GET /demo/scenarios`
- `POST /demo/run/hr_screening`
- `POST /demo/run/credit_scoring`
- `POST /demo/run/social_scoring`

These scenarios are intended to illustrate how the rule engine behaves under different modeled control sets.

Important note:

- a compliant result means the modeled controls appear satisfied
- it does not mean the system is generally benign or exempt from deeper review

## Audit Core Omission In This Public Edition

The original working project includes a fuller live-audit direction, but this staged public edition intentionally omits the most sensitive audit core.

Omitted from the public edition:

- the full live audit runner
- the detailed proprietary scenario library
- the highest-leverage evaluator content used to exercise target APIs in depth

Why this was removed:

- it is one of the most commercially distinctive parts of the project
- it is not necessary to prove backend, product, and scoring capability in a portfolio context
- it reduces direct competitor lift from the public repository

The public edition therefore focuses on what it can prove cleanly:

- compliance scoring
- guidance generation
- evidence-chain and certificate concepts
- frontend and documentation quality

## Demo Frontend

The file `demo.html` is a standalone frontend that can be opened directly in a browser.

What it supports:

- running public demo scenarios
- submitting custom checkbox-based assessments
- reading returned compliance guidance
- showing where audit-oriented capabilities fit in the product story

The frontend uses `http://localhost:18000` by default. It can be overridden with a query parameter or local storage.

Public edition note:

- public demo scenarios work without authentication
- protected scoring requires a valid Bearer token from the API
- the visible audit panel is retained as product context, but the live audit core is intentionally omitted from this public edition

## Media

This portfolio edition includes visual showcase assets:

- screenshots in `media/screenshots/`
- a short frontend walkthrough video in `media/video/frontend-demo.mp4`

These assets are intended to make the project easier to evaluate quickly as a portfolio piece.

## Repository Hygiene

This staged public edition is meant to be publishable with minimal cleanup. Runtime caches, local virtual environments, and other rebuildable artifacts should stay out of version control.

## Open Source And Collaboration

This public edition is released under Apache-2.0.

That choice is intentional. The goal is for this repository to be friendly, readable, and genuinely reusable as part of the broader Sampo AI OS showcase, rather than defensive or hostile toward collaboration.

What that means in practice:

- reuse, experimentation, and discussion are welcome under the Apache-2.0 terms
- issues, suggestions, and thoughtful improvements are welcome
- this repository is a curated public edition, so some higher-leverage internal components remain outside the public repo by design

If you are evaluating this repository, it should be read as both:

- an open-source codebase that others can learn from and build on
- a public-facing Sampo AI OS product output that demonstrates how the digital office turns opportunities into reviewable software artifacts

## Certificate Verification

Certificates are deterministic JSON documents with a SHA-256 fingerprint.

Verification principle:

1. remove the `fingerprint` field
2. serialize the remaining JSON with sorted keys
3. compute SHA-256
4. compare the computed hash to the claimed fingerprint

The API endpoint `POST /audit/verify/certificate` performs this verification and also returns any embedded compliance guidance.

## Project Structure

```text
main.py                      FastAPI routes and application bootstrap
database.py                  SQLAlchemy engine and DB helpers
demo.html                    Standalone browser demo
models/
	audit_session.py           Audit session and evidence schema models retained for architecture context
	ethical_rule.py            Rule model and scoring response schemas
	test_scenario.py           Public placeholder for the internal scenario library
	user.py                    User and token schemas
services/
	ethics_scoring.py          Rule-based scoring engine and guidance builder
	evidence_chain.py          Hash-chain append and verification logic
	certificate.py             Certificate verification and certificate-shape logic
tests/
	test_scoring.py            Scoring and rule serialization tests
```

## Testing

Run the full test suite:

```bash
pytest tests -v
```

Current regression coverage includes:

- scoring logic
- rule serialization
- selected evidence and certificate concepts retained in the public code

## Known Limitations

- The modeled rule set is intentionally narrow and should not be treated as a complete legal implementation of the EU AI Act.
- The React dashboard prototype is not the primary maintained frontend; `demo.html` is the main interactive demo in this repository.
- The live audit runner and detailed scenario library are intentionally omitted from this public edition to avoid publishing the most commercially sensitive evaluator core.
- Pydantic emits warnings for `model_`-prefixed field names. This does not block runtime behavior, but it should be cleaned up for polish.
- This application provides compliance-oriented technical guidance, not legal advice.

## Troubleshooting

### API is not reachable

- Check `http://localhost:18000/health`
- Confirm Docker containers are healthy with `docker compose ps`
- If port `18000` is busy, set `APP_PORT` to another value

### Authentication fails during Docker usage

The project pins `bcrypt==4.0.1` because newer `bcrypt` releases are incompatible with `passlib==1.7.4` in this setup.

### Demo opens but shows no data

- Confirm the backend is running
- Confirm the demo points to the correct API base URL
- Test a known public endpoint such as `POST /demo/run/credit_scoring`

## Positioning

AI Ethics OS is the application layer.
Sampo AI OS is the digital office and platform identity behind the broader system.

In this repository, that means the tool is not framed as a passive scorecard. It is intended to actively support teams in building, testing, auditing, and maintaining solutions that stay inside modeled EU AI Act boundaries.

This public repository should also be understood as a Sampo AI OS showcase: not just a code dump, but an intentional product artifact from the digital office and an example of product framing, public documentation quality, and collaboration-friendly engineering.
