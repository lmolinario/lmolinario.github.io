# Digital Risk Scanner

Digital Risk Scanner is a backend-first SaaS-style platform that scans a company's external digital exposure, assigns a risk score, and generates an actionable report with business-oriented remediation guidance.

The project is designed as a lightweight external risk assessment product that can be used both as a standalone service and as a sales-enablement tool for agencies, consultants, or managed security providers.

---

## Current Status

This repository already contains a working MVP.

Implemented capabilities include:

- Domain normalization and validation
- Asynchronous scan execution with Celery and Redis
- DNS security checks
  - SPF
  - DMARC
  - MX
  - DNS lookup handling
- TLS / SSL checks
- Risk scoring
- PostgreSQL persistence
- Findings API
- Report generation
- HTML full report
- Stripe-based paid unlock flow
- PDF export
- Business-oriented finding enrichment

The current focus is no longer core architecture, but product refinement, consistency, and commercial presentation quality.

---

## Product Flow

1. A user submits a domain
2. The platform normalizes and validates the target
3. A background worker executes the scan
4. Findings are stored and scored
5. A teaser report is shown
6. The full report is unlocked after payment
7. The user can access:
   - the full HTML report
   - the downloadable PDF report

---

## Core Capabilities

### Scanning
- Domain validation and normalization
- DNS checks for email-related security posture
- TLS / SSL certificate inspection
- Basic external exposure signals

### Reporting
- Risk score calculation
- Severity breakdown
- Executive summary
- Prioritized remediation guidance
- Enriched findings with technical and business framing
- Full HTML report rendering
- PDF report generation

### Commercial Flow
- Locked teaser report
- Stripe checkout flow
- Unlock logic for paid reports
- Post-payment access to the full report and PDF export

---

## Architecture

The application is structured as a backend-first service with asynchronous execution and report rendering.

### Main components
- **FastAPI** for API and server-rendered endpoints
- **PostgreSQL** for persistence
- **Redis** for background task coordination
- **Celery** for asynchronous scan execution
- **Stripe** for checkout and unlock flow
- **Report service** for HTML and PDF report generation

---

## Tech Stack

- FastAPI
- SQLAlchemy
- PostgreSQL
- Redis
- Celery
- dnspython
- Stripe
- ReportLab
- Jinja2
- Docker
- Docker Compose

---

## Main Endpoints

### Scans
- `POST /api/scans`
- `GET /api/scans/{scan_id}`
- `GET /api/scans/{scan_id}/findings`

### Reports
- `GET /api/reports/{scan_id}`
- `GET /api/pdf/{scan_id}`

### Billing
- `POST /api/billing/checkout/{scan_id}`
- `POST /api/billing/webhook`

---

## Report Structure

The current report logic is built around a commercially useful structure.

Typical sections include:

- Risk Overview
- Severity Breakdown
- Executive Summary
- What to Fix First
- Key Observations
- Remediation Plan
- Detailed Findings

Each finding can include:
- severity
- business title
- technical title
- description
- business impact
- why it matters
- effort
- technical complexity
- remediation steps
- recommendation
- evidence

---

## Repository Goal

The purpose of this project is not to become a full enterprise ASM platform.

The current product direction is to remain:

- lightweight
- easy to understand
- commercially useful
- fast to demo
- suitable for agencies, consultants, and SMB-oriented security services

---

## Local Development

### Requirements
- Docker
- Docker Compose

### Start the stack

```bash
cp .env.example .env
docker compose up --build
````

Depending on your setup, the application will expose:

* API endpoints
* background worker services
* database and Redis services

---

## Suggested Environment Variables

The exact environment variables depend on the current implementation, but typical values include:

* database connection string
* Redis connection string
* Stripe secret key
* Stripe webhook secret
* application base URL
* PDF/report-related settings

Use your local `.env` file to configure runtime behavior.

---

## Development Priorities

The current priorities are:

1. **Language consistency across the repository**

   * remove mixed Italian/English content
   * keep README, comments, UI text, and report terminology fully aligned

2. **HTML report refinement**

   * bring the full HTML report to the same quality level as the PDF
   * improve perceived polish and premium presentation

3. **More granular DNS findings**

   * refine classification of DNS-related issues
   * improve business titles and remediation specificity

4. **Commercial presentation quality**

   * strengthen positioning as a lightweight report product
   * improve clarity for agencies and consultants using it in sales workflows

---

## Intended Positioning

Digital Risk Scanner is best positioned as:

* a lightweight external digital risk report
* a lead-generation or pre-sales diagnostic tool
* a small-footprint security visibility product
* a white-label-friendly assessment layer for agencies and consultants

---

## Non-Goals

At this stage, the project is **not** trying to be:

* a full vulnerability scanner
* a full enterprise exposure management suite
* a complete continuous attack surface management platform
* a replacement for enterprise-grade ASM or CTI products

The value lies in clarity, speed, simplicity, and report quality.

---

## Current Maturity

This is no longer just a proof of concept.

It is currently a **working MVP** with:

* scanning
* persistence
* reporting
* billing
* PDF generation

The next step is to make it more consistent, polished, and commercially credible.

---

## License

Add the appropriate license information here if you plan to publish or distribute the project.


