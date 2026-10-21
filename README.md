# ⚡ LogSense AI — AI-Powered CI/CD Log Analyzer & Observability SaaS

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)]()
[![Free AI Models](https://img.shields.io/badge/LLMs-Gemini%20%7C%20Groq%20%7C%20OpenRouter%20%7C%20Offline-orange.svg)]()
[![GitHub Actions Ready](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions%20Ready-purple.svg)]()

> **LogSense AI** is a production-grade, zero-dependency AIOps diagnostic SaaS platform that connects to GitHub Actions workflows, intercepts CI/CD build and test failures, isolates error traces, and executes LLM-driven root-cause reasoning to suggest instant code patches and remediation steps.

Developed with ❤️ by **Yash Dodani** ([yashdodani.me](https://yashdodani.me) • [GitHub](https://github.com/Yash-Dodani)).

---

## 📌 Architecture & System Flow

```text
       ┌────────────────────────────────────────────────────────┐
       │     GitHub Actions / CI Pipelines / Terminal Dumps    │
       └───────────────────────────┬────────────────────────────┘
                                   │
                                   ▼
       ┌────────────────────────────────────────────────────────┐
       │           Log Ingestion & Context Windowing            │
       │    (Sanitizes noise, extracts stack traces & exit codes) │
       └───────────────────────────┬────────────────────────────┘
                                   │
                                   ▼
                   ┌───────────────────────────────┐
                   │    Multi-Provider AI Router   │
                   └───────────────┬───────────────┘
                                   │
         ┌─────────────────────────┼─────────────────────────┐
         ▼                         ▼                         ▼
┌─────────────────┐       ┌─────────────────┐       ┌───────────────────┐
│  Google Gemini  │       │    Groq Llama   │       │  Smart Heuristics │
│  (Free Tier)    │       │   (Sub-second)  │       │  (100% Offline)   │
└───────┬─────────┘       └────────┬────────┘       └─────────┬─────────┘
        │                          │                          │
        └──────────────────────────┼──────────────────────────┘
                                   ▼
       ┌────────────────────────────────────────────────────────┐
       │             Structured Remediation Engine              │
       │  • Root Cause Diagnosis    • Actionable Code Diffs     │
       │  • Severity & Category     • Prevention Guidelines     │
       └───────────────────────────┬────────────────────────────┘
                                   │
         ┌─────────────────────────┼─────────────────────────┐
         ▼                         ▼                         ▼
┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
│ SaaS Web UI &    │      │  GitHub Actions  │      │  Slack / Discord │
│ Repo Inspector   │      │   Step Summary   │      │  Webhook Alerts  │
└──────────────────┘      └──────────────────┘      └──────────────────┘
```

---

## ⚡ Core Features

- **🐙 Live GitHub Actions Pipeline Inspector**: Connect with a GitHub Personal Access Token or explore any public repository/organization. View real-time workflow runs and click to auto-diagnose failed jobs.
- **⚡ Zero External Dependencies**: Built entirely with Python's standard library (`http.server`, `urllib.request`, `json`, `re`). Starts in milliseconds with no `pip install` required.
- **🧠 Multi-Provider AI Support**:
  - **Google Gemini 1.5/2.0 Flash** (Free API tier)
  - **Groq Llama 3.3 70B** (Ultra-fast sub-second inferences)
  - **OpenRouter Free Models** (Llama 3.3, Mistral)
  - **100% Offline Smart Heuristics** (Runs with zero API keys)
- **📋 Instant Code Patch & Remediation**: Generates clear error explanations, copy-paste diff patches, CLI commands, and prevention guidelines.
- **📊 Incident Analytics & History**: Persistent incident tracking with confidence scoring and error domain categorization.
- **🚀 One-Click Export**: Export directly as Markdown (for GitHub PR comments / Issue tickets) or JSON payloads.

---

## 🚀 Quickstart Guide

### 1. Run the SaaS Web Dashboard Locally

```bash
# Clone the repository
git clone https://github.com/Yash-Dodani/ai-cicd-log-analyzer.git
cd ai-cicd-log-analyzer

# Start the dashboard (Zero dependencies required!)
python web_server.py
```

Open your browser at **`http://localhost:8080`**.

---

### 2. Run via CLI

Analyze any log file directly from your terminal:

```bash
# Offline heuristic mode (No API key needed)
python analyzer.py --log samples/flutter_build_fail.log

# Using Google Gemini Free API
python analyzer.py --log samples/python_pytest_fail.log --provider gemini --api-key YOUR_GEMINI_KEY

# Using Groq Llama 3.3 Free API
python analyzer.py --log samples/docker_build_fail.log --provider groq --api-key YOUR_GROQ_KEY
```

---

### 3. Docker Deployment

```bash
docker-compose up -d
```

The SaaS dashboard will be live at `http://localhost:8080`.

---

## ⚙️ Environment Variables

| Variable | Description |
| :--- | :--- |
| `PORT` | Server listening port (default: `8080`) |
| `GEMINI_API_KEY` | Optional Google Gemini API Key |
| `GROQ_API_KEY` | Optional Groq API Key |
| `SLACK_WEBHOOK_URL` | Optional Slack/Discord webhook for alerts |

---

## 📄 License

MIT License © 2026 [Yash Dodani](https://github.com/Yash-Dodani).
