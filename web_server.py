#!/usr/bin/env python3
"""
CI Log Analyzer — Production AIOps Observability SaaS Platform
Author: Yash Dodani (github.com/Yash-Dodani)
Features:
 - Exact UI match with design specification (Dashboard, Analyze Logs, Results, History, Settings)
 - Live GitHub API Integration (Public & Private repos, Actions runs, Job logs)
 - Multi-LLM Reasoning (OpenRouter Llama 3.3, Groq, Gemini, Offline Heuristics)
 - Fix Prompts (for Cursor / Copilot) & Step-by-Step CLI Remediation
 - Ottie Animated Mascot Integrations
"""

import os
import sys
import json
import socket
import urllib.request
import urllib.error
import urllib.parse
import mimetypes
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, List, Optional

# Safe UTF-8 encoding on Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Simple .env loader with zero dependencies
def load_env_file(filepath=os.path.join(BASE_DIR, ".env")):
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if k not in os.environ:
                            os.environ[k] = v
        except Exception:
            pass

load_env_file()

import analyzer

# OpenRouter Key loaded from environment
DEFAULT_OPENROUTER_KEY = os.environ.get("OPENROUTER_API_KEY", "")

def get_free_port(preferred_port: int = 5050) -> int:
    for p in range(preferred_port, preferred_port + 50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('0.0.0.0', p))
                return p
            except OSError:
                continue
    return preferred_port

PORT = int(os.environ.get("PORT", 0)) or get_free_port(5050)
HISTORY_FILE = os.path.join(BASE_DIR, "incident_history.json")


def load_history() -> List[Dict[str, Any]]:
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return get_default_history()
    return get_default_history()


def get_default_history() -> List[Dict[str, Any]]:
    return [
        {
            "id": "inc-101",
            "title": "Unit tests failed - test_auth.py",
            "category": "Authentication Error",
            "severity": "High",
            "time_ago": "2 hours ago",
            "timestamp": "2026-10-21T06:14:00Z",
            "env_info": "pushed 2 hours ago • Python • GitHub Actions",
            "confidence": "0.89",
            "root_cause": "Invalid or missing authentication credentials causing 401 Unauthorized during login endpoint tests.",
            "summary": "The test 'test_login' is failing because the API endpoint '/login' is returning a 401 Unauthorized status code instead of 200 OK. This usually happens when authentication credentials are missing, invalid, or the authentication logic is not properly implemented.",
            "relevant_lines": "tests/test_auth.py:12\n>  response = client.post(\"/login\", json={\"email\": \"test@example.com\"})\nE  assert response.status_code == 200\nE  assert 401 == 200\nE  + where 401 = <Response [401 Unauthorized]>.status_code",
            "affected_tests": "1 test failed",
            "estimated_fix_time": "5 - 10 minutes",
            "ai_suggestions": [
                {"title": "Check Authentication Headers", "desc": "Ensure the correct API key or token is being sent in the request headers."},
                {"title": "Verify Test Data", "desc": "Make sure the test user exists in the database and the credentials are correct."},
                {"title": "Check Environment Variables", "desc": "Verify that authentication-related environment variables are properly set in your CI environment."},
                {"title": "Review API Endpoint", "desc": "Check if the /login endpoint requires additional parameters or has changed."}
            ],
            "fix_prompt": "Fix pytest authentication test failure in tests/test_auth.py: The endpoint /login returns 401 Unauthorized because valid test credentials and mock JWT authorization headers are missing. Update the test fixture to inject a valid mock auth token.",
            "fix_steps": [
                "1. Open tests/test_auth.py and pass headers={'Authorization': 'Bearer test-token'} in the client.post payload.",
                "2. Ensure mock authentication backend is enabled in conftest.py.",
                "3. Re-run local test: pytest tests/test_auth.py -v"
            ]
        },
        {
            "id": "inc-102",
            "title": "Build succeeded",
            "category": "Success",
            "severity": "Success",
            "time_ago": "5 hours ago",
            "timestamp": "2026-10-21T03:14:00Z",
            "env_info": "main branch • Node.js • GitHub Actions",
            "confidence": "1.00",
            "root_cause": "All build artifacts and test suites completed with exit code 0.",
            "summary": "Pipeline executed all linting, TypeScript compilation, and unit tests cleanly with 0 regressions detected.",
            "relevant_lines": "npm run build\nCompiled successfully in 14.2s\nDone in 16.4s.",
            "affected_tests": "All tests passed",
            "estimated_fix_time": "0 minutes",
            "ai_suggestions": [
                {"title": "Automated Deployment", "desc": "Workflow ready for staging canary deployment."},
                {"title": "Cache Optimization", "desc": "Node modules cache hit saved 42 seconds in pipeline runtime."}
            ],
            "fix_prompt": "No fix needed. Build is green.",
            "fix_steps": ["Deploy to staging environment."]
        },
        {
            "id": "inc-103",
            "title": "ModuleNotFoundError: No module named 'requests'",
            "category": "Dependency Error",
            "severity": "Medium",
            "time_ago": "1 day ago",
            "timestamp": "2026-10-20T08:14:00Z",
            "env_info": "feature/auth • Python • GitLab CI",
            "confidence": "0.98",
            "root_cause": "The Python runtime could not find package 'requests' because it is not declared in requirements.txt.",
            "summary": "Python module import failure during test initialization. Package 'requests' was imported in src/api_client.py without being installed.",
            "relevant_lines": "Traceback (most recent call last):\n  File \"src/api_client.py\", line 3, in <module>\n    import requests\nModuleNotFoundError: No module named 'requests'",
            "affected_tests": "3 tests blocked",
            "estimated_fix_time": "2 minutes",
            "ai_suggestions": [
                {"title": "Add to requirements.txt", "desc": "Add requests>=2.31.0 into your project requirements.txt."},
                {"title": "Update CI setup step", "desc": "Verify pip install -r requirements.txt is executed before tests run."}
            ],
            "fix_prompt": "Add 'requests>=2.31.0' to requirements.txt and verify pyproject.toml dependencies.",
            "fix_steps": [
                "1. Run: pip install requests",
                "2. Run: pip freeze | grep requests >> requirements.txt",
                "3. Commit requirements.txt and push branch."
            ]
        }
    ]


def save_history(entry: Dict[str, Any]):
    history = load_history()
    # Check if id exists
    history = [h for h in history if h.get("id") != entry.get("id")]
    history.insert(0, entry)
    history = history[:50]
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2)
    except Exception as e:
        print(f"[!] Could not save incident history: {e}")


HTML_DASHBOARD = r'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CI Log Analyzer — AI-Powered CI/CD Observability</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #080d1a;
      --sidebar-bg: #0c1322;
      --card-bg: #10192d;
      --card-inner: #0b1220;
      --border: rgba(255, 255, 255, 0.07);
      --border-hover: rgba(99, 102, 241, 0.4);
      --accent: #4f46e5;
      --accent-gradient: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
      --accent-glow: rgba(99, 102, 241, 0.35);
      --text: #ffffff;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --danger: #ef4444;
      --danger-bg: rgba(239, 68, 68, 0.12);
      --danger-border: rgba(239, 68, 68, 0.3);
      --warning: #f59e0b;
      --warning-bg: rgba(245, 158, 11, 0.12);
      --success: #10b981;
      --success-bg: rgba(16, 185, 129, 0.12);
      --radius-sm: 8px;
      --radius-md: 12px;
      --radius-lg: 16px;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      overflow-x: hidden;
    }

    /* ================================================= */
    /* LEFT SIDEBAR                                      */
    /* ================================================= */
    .sidebar {
      width: 240px;
      background: var(--sidebar-bg);
      border-right: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      padding: 20px 16px;
      flex-shrink: 0;
      height: 100vh;
      position: sticky;
      top: 0;
      z-index: 40;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 4px 8px 24px 8px;
      text-decoration: none;
    }
    .brand-icon {
      width: 32px;
      height: 32px;
      background: linear-gradient(135deg, #6366f1, #8b5cf6);
      border-radius: 9px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #fff;
      font-size: 16px;
      box-shadow: 0 0 12px rgba(99, 102, 241, 0.4);
    }
    .brand-text {
      font-size: 15px;
      font-weight: 800;
      letter-spacing: -0.3px;
      color: #fff;
    }

    .nav-menu {
      display: flex;
      flex-direction: column;
      gap: 4px;
      flex: 1;
    }
    .nav-item {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 10px 14px;
      border-radius: var(--radius-sm);
      color: var(--text-muted);
      text-decoration: none;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      border: 1px solid transparent;
      transition: all 0.2s;
    }
    .nav-item:hover {
      color: #fff;
      background: rgba(255, 255, 255, 0.04);
    }
    .nav-item.active {
      background: rgba(79, 70, 229, 0.16);
      color: #818cf8;
      border: 1px solid rgba(99, 102, 241, 0.3);
    }

    /* SIDEBAR PROMO CARD */
    .sidebar-promo {
      background: linear-gradient(145deg, rgba(79, 70, 229, 0.2), rgba(139, 92, 246, 0.1));
      border: 1px solid rgba(99, 102, 241, 0.3);
      border-radius: var(--radius-md);
      padding: 14px;
      position: relative;
      overflow: hidden;
    }
    .sidebar-promo-title {
      font-size: 12px;
      font-weight: 700;
      color: #fff;
      margin-bottom: 4px;
    }
    .sidebar-promo-desc {
      font-size: 11px;
      color: var(--text-muted);
      line-height: 1.4;
    }
    .sidebar-promo-img {
      position: absolute;
      right: -10px;
      bottom: -15px;
      width: 60px;
      height: 60px;
      object-fit: contain;
      opacity: 0.85;
      pointer-events: none;
    }

    /* ================================================= */
    /* MAIN WRAPPER & TOPBAR                             */
    /* ================================================= */
    .main-wrapper {
      flex: 1;
      display: flex;
      flex-direction: column;
      min-width: 0;
      overflow-y: auto;
    }

    .topbar {
      height: 64px;
      border-bottom: 1px solid var(--border);
      padding: 0 32px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: rgba(8, 13, 26, 0.8);
      backdrop-filter: blur(12px);
      position: sticky;
      top: 0;
      z-index: 30;
    }

    .search-box {
      display: flex;
      align-items: center;
      gap: 10px;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 6px 14px;
      width: 320px;
      font-size: 12px;
      color: var(--text-muted);
      cursor: text;
    }
    .search-box input {
      background: transparent;
      border: none;
      outline: none;
      color: #fff;
      font-family: inherit;
      font-size: 12px;
      width: 100%;
    }
    .kbd-shortcut {
      background: rgba(255, 255, 255, 0.08);
      border: 1px solid var(--border);
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 10px;
      font-family: 'JetBrains Mono', monospace;
      color: var(--text-dim);
    }

    .user-profile {
      display: flex;
      align-items: center;
      gap: 12px;
      cursor: pointer;
    }
    .user-avatar {
      width: 34px;
      height: 34px;
      border-radius: 50%;
      background: linear-gradient(135deg, #f97316, #fb923c);
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      color: #fff;
      font-size: 13px;
    }
    .user-info {
      text-align: right;
    }
    .user-name {
      font-size: 13px;
      font-weight: 700;
      color: #fff;
    }
    .user-role {
      font-size: 11px;
      color: var(--text-dim);
    }

    /* ================================================= */
    /* VIEW CONTAINERS                                   */
    /* ================================================= */
    .view-container {
      display: none;
      padding: 32px;
      max-width: 1280px;
      margin: 0 auto;
      width: 100%;
    }
    .view-container.active {
      display: block;
      animation: fadeIn 0.25s ease-out;
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(6px); }
      to { opacity: 1; transform: translateY(0); }
    }

    /* BUTTONS */
    .btn-primary {
      background: var(--accent-gradient);
      color: #fff;
      border: none;
      border-radius: var(--radius-sm);
      font-family: inherit;
      font-size: 13px;
      font-weight: 700;
      padding: 11px 22px;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      cursor: pointer;
      box-shadow: 0 4px 14px var(--accent-glow);
      transition: all 0.2s;
    }
    .btn-primary:hover {
      opacity: 0.95;
      transform: translateY(-1px);
    }
    .btn-outline {
      background: var(--card-bg);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      font-family: inherit;
      font-size: 13px;
      font-weight: 600;
      padding: 11px 20px;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      cursor: pointer;
      transition: all 0.2s;
    }
    .btn-outline:hover {
      border-color: var(--accent);
      background: var(--card-inner);
    }

    /* ================================================= */
    /* 1. DASHBOARD VIEW                                 */
    /* ================================================= */
    .dashboard-hero {
      display: grid;
      grid-template-columns: 1.2fr 0.8fr;
      align-items: center;
      gap: 24px;
      margin-bottom: 32px;
    }
    @media (max-width: 900px) {
      .dashboard-hero { grid-template-columns: 1fr; }
    }

    .hero-title {
      font-size: 32px;
      font-weight: 800;
      letter-spacing: -1px;
      line-height: 1.2;
      margin-bottom: 12px;
    }
    .hero-title span {
      background: linear-gradient(135deg, #818cf8 0%, #c084fc 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .hero-sub {
      font-size: 14px;
      color: var(--text-muted);
      line-height: 1.5;
      margin-bottom: 24px;
      max-width: 520px;
    }
    .hero-actions {
      display: flex;
      gap: 12px;
    }

    .hero-illustration-box {
      background: radial-gradient(circle at center, rgba(99, 102, 241, 0.15), transparent 70%);
      display: flex;
      align-items: center;
      justify-content: center;
      position: relative;
      height: 200px;
    }
    .hero-mascot {
      width: 170px;
      height: 170px;
      object-fit: contain;
      filter: drop-shadow(0 10px 20px rgba(0,0,0,0.5));
      animation: float 4s ease-in-out infinite;
    }
    @keyframes float {
      0%, 100% { transform: translateY(0); }
      50% { transform: translateY(-8px); }
    }

    /* STATS GRID */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
      margin-bottom: 32px;
    }
    @media (max-width: 900px) {
      .stats-grid { grid-template-columns: repeat(2, 1fr); }
    }
    .stat-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      padding: 18px;
      position: relative;
    }
    .stat-card-title {
      font-size: 12px;
      font-weight: 600;
      color: var(--text-muted);
    }
    .stat-val-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-top: 8px;
    }
    .stat-number {
      font-size: 28px;
      font-weight: 800;
      letter-spacing: -0.5px;
      color: #fff;
    }
    .stat-icon {
      width: 32px;
      height: 32px;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 14px;
    }
    .stat-trend {
      font-size: 11px;
      margin-top: 6px;
      color: var(--text-dim);
    }
    .stat-trend.green { color: #34d399; }
    .stat-trend.red { color: #f87171; }

    /* RECENT ANALYSES LIST */
    .section-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      padding: 20px;
    }
    .section-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
    }
    .section-title {
      font-size: 15px;
      font-weight: 700;
      color: #fff;
    }
    .section-link {
      color: #818cf8;
      text-decoration: none;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
    }

    .analysis-list {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .analysis-item {
      background: var(--card-inner);
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      padding: 14px 18px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      cursor: pointer;
      transition: all 0.2s;
    }
    .analysis-item:hover {
      border-color: var(--border-hover);
      transform: translateX(3px);
    }
    .item-left {
      display: flex;
      align-items: center;
      gap: 14px;
    }
    .status-circle {
      width: 24px;
      height: 24px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 11px;
      font-weight: 800;
    }
    .status-circle.error { background: var(--danger-bg); color: #f87171; border: 1px solid var(--danger-border); }
    .status-circle.success { background: var(--success-bg); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }

    .item-title {
      font-size: 13px;
      font-weight: 700;
      color: #fff;
    }
    .item-sub {
      font-size: 11px;
      color: var(--text-dim);
      margin-top: 3px;
    }
    .item-right {
      display: flex;
      align-items: center;
      gap: 16px;
    }
    .badge-pill {
      font-size: 11px;
      font-weight: 700;
      padding: 3px 10px;
      border-radius: 12px;
      font-family: 'JetBrains Mono', monospace;
    }
    .badge-pill.High { background: var(--danger-bg); color: #f87171; border: 1px solid var(--danger-border); }
    .badge-pill.Success { background: var(--success-bg); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge-pill.Medium { background: var(--warning-bg); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }
    .badge-pill.Critical { background: rgba(225, 29, 72, 0.2); color: #fb7185; border: 1px solid rgba(225, 29, 72, 0.4); }

    /* ================================================= */
    /* 2. ANALYZE LOGS VIEW                              */
    /* ================================================= */
    .page-header {
      margin-bottom: 24px;
    }
    .page-title {
      font-size: 22px;
      font-weight: 800;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .page-sub {
      font-size: 13px;
      color: var(--text-muted);
      margin-top: 4px;
    }

    .analyze-tabs-bar {
      display: flex;
      gap: 8px;
      margin-bottom: 16px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 10px;
    }
    .analyze-subtab {
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-family: inherit;
      font-size: 13px;
      font-weight: 600;
      padding: 8px 14px;
      border-radius: 6px;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 8px;
      transition: all 0.2s;
    }
    .analyze-subtab:hover { color: #fff; background: rgba(255, 255, 255, 0.04); }
    .analyze-subtab.active {
      background: var(--card-bg);
      color: #818cf8;
      border: 1px solid rgba(99, 102, 241, 0.3);
    }

    /* CODE TERMINAL */
    .editor-wrapper {
      background: #080c16;
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      overflow: hidden;
      margin-bottom: 16px;
    }
    .editor-textarea {
      width: 100%;
      height: 340px;
      background: transparent;
      border: none;
      color: #e2e8f0;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      line-height: 1.6;
      padding: 16px;
      resize: vertical;
      outline: none;
    }
    .editor-footer {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 8px 16px;
      background: #060a12;
      border-top: 1px solid var(--border);
      font-size: 11px;
      color: var(--text-dim);
    }
    .clear-btn {
      background: transparent;
      border: none;
      color: var(--danger);
      font-size: 11px;
      font-weight: 600;
      cursor: pointer;
    }

    .btn-full {
      width: 100%;
      justify-content: center;
      padding: 14px;
      font-size: 14px;
    }

    /* GITHUB EXPLORER SECTION */
    .github-connect-box {
      background: var(--card-inner);
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      padding: 18px;
      margin-bottom: 16px;
      display: flex;
      gap: 12px;
    }
    .input-field {
      background: #060a12;
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      color: #fff;
      font-family: inherit;
      font-size: 13px;
      padding: 10px 14px;
      outline: none;
      flex: 1;
    }
    .input-field:focus { border-color: var(--accent); }

    /* ================================================= */
    /* 3. ANALYSIS RESULTS VIEW                          */
    /* ================================================= */
    .results-top-actions {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 20px;
    }
    .back-btn {
      color: var(--text-muted);
      cursor: pointer;
      font-size: 13px;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .back-btn:hover { color: #fff; }

    /* RED ALERT BANNER */
    .alert-banner {
      background: linear-gradient(135deg, rgba(239, 68, 68, 0.12), rgba(153, 27, 27, 0.08));
      border: 1px solid var(--danger-border);
      border-radius: var(--radius-md);
      padding: 20px;
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      margin-bottom: 24px;
    }
    .alert-left {
      display: flex;
      gap: 14px;
    }
    .alert-icon-box {
      width: 36px;
      height: 36px;
      background: rgba(239, 68, 68, 0.2);
      border: 1px solid rgba(239, 68, 68, 0.4);
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #f87171;
      font-size: 16px;
      flex-shrink: 0;
    }
    .alert-title {
      font-size: 16px;
      font-weight: 800;
      color: #fff;
    }
    .alert-sub {
      font-size: 13px;
      color: #cbd5e1;
      margin-top: 4px;
      line-height: 1.4;
      max-width: 680px;
    }
    .alert-badges {
      display: flex;
      gap: 8px;
      align-items: center;
    }

    /* RESULT TABS */
    .result-nav-tabs {
      display: flex;
      gap: 8px;
      margin-bottom: 20px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 8px;
    }
    .res-tab {
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-family: inherit;
      font-size: 13px;
      font-weight: 600;
      padding: 6px 14px;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.2s;
    }
    .res-tab.active {
      background: var(--card-bg);
      color: #818cf8;
      border: 1px solid rgba(99, 102, 241, 0.3);
    }

    /* 4 INSIGHT CARDS */
    .insights-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 14px;
      margin-bottom: 24px;
    }
    @media (max-width: 900px) {
      .insights-grid { grid-template-columns: repeat(2, 1fr); }
    }
    .insight-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      padding: 14px;
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .insight-icon-box {
      width: 32px;
      height: 32px;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 14px;
    }
    .insight-label {
      font-size: 11px;
      color: var(--text-dim);
      font-weight: 600;
    }
    .insight-val {
      font-size: 12px;
      font-weight: 700;
      color: #fff;
      margin-top: 2px;
    }

    /* TWO COL DETAIL SPLIT */
    .detail-grid {
      display: grid;
      grid-template-columns: 1.15fr 0.85fr;
      gap: 20px;
    }
    @media (max-width: 900px) {
      .detail-grid { grid-template-columns: 1fr; }
    }

    .detail-box {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      padding: 20px;
      margin-bottom: 16px;
    }
    .detail-box-title {
      font-size: 13px;
      font-weight: 700;
      color: #fff;
      margin-bottom: 10px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    /* AI SUGGESTIONS LIST */
    .suggestion-item {
      display: flex;
      gap: 12px;
      padding: 12px 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
    }
    .suggestion-num {
      width: 22px;
      height: 22px;
      border-radius: 50%;
      background: rgba(99, 102, 241, 0.2);
      color: #818cf8;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 11px;
      font-weight: 800;
      flex-shrink: 0;
    }
    .suggestion-title {
      font-size: 13px;
      font-weight: 700;
      color: #fff;
    }
    .suggestion-desc {
      font-size: 12px;
      color: var(--text-muted);
      margin-top: 3px;
      line-height: 1.4;
    }

    /* CODE BOX */
    .code-display {
      background: #000;
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      padding: 12px;
      color: #38bdf8;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      white-space: pre-wrap;
      line-height: 1.5;
      overflow-x: auto;
    }

    /* ================================================= */
    /* 4. SETTINGS VIEW                                  */
    /* ================================================= */
    .settings-tabs {
      display: flex;
      gap: 8px;
      margin-bottom: 20px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 8px;
    }

    /* MODAL SEARCH */
    .modal-overlay {
      display: none;
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0,0,0,0.7);
      backdrop-filter: blur(4px);
      z-index: 100;
      align-items: center;
      justify-content: center;
    }
    .modal-box {
      background: var(--card-bg);
      border: 1px solid var(--border-hover);
      border-radius: var(--radius-md);
      width: 520px;
      max-width: 90%;
      padding: 20px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.6);
    }
  </style>
</head>
<body>

  <!-- =============================================== -->
  <!-- LEFT SIDEBAR                                    -->
  <!-- =============================================== -->
  <aside class="sidebar">
    <div>
      <a href="#" class="brand" onclick="switchView('dashboard')">
        <div class="brand-icon">🤖</div>
        <div class="brand-text">CI Log Analyzer</div>
      </a>

      <nav class="nav-menu">
        <div class="nav-item active" id="nav-dashboard" onclick="switchView('dashboard')">
          <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path></svg>
          Dashboard
        </div>
        <div class="nav-item" id="nav-analyze" onclick="switchView('analyze')">
          <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line></svg>
          Analyze Logs
        </div>
        <div class="nav-item" id="nav-history" onclick="switchView('history')">
          <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
          History
        </div>
        <div class="nav-item" id="nav-integrations" onclick="switchView('integrations')">
          <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>
          Integrations
        </div>
        <div class="nav-item" id="nav-settings" onclick="switchView('settings')">
          <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
          Settings
        </div>
      </nav>
    </div>

    <!-- SIDEBAR PROMO WITH OTTIE -->
    <div class="sidebar-promo">
      <div class="sidebar-promo-title">AI Powered Log Analysis</div>
      <div class="sidebar-promo-desc">Turn CI/CD failures into clear solutions with AI</div>
      <img src="/assets/ottie/hello 1.png" class="sidebar-promo-img" alt="Ottie Mascot">
    </div>
  </aside>

  <!-- =============================================== -->
  <!-- MAIN CONTENT AREA                               -->
  <!-- =============================================== -->
  <div class="main-wrapper">

    <!-- TOPBAR -->
    <header class="topbar">
      <div class="search-box" onclick="focusSearch()">
        <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
        <input type="text" id="globalSearch" placeholder="Search analysis history..." onkeydown="handleSearchKey(event)">
        <span class="kbd-shortcut">Ctrl + K</span>
      </div>

      <div class="user-profile" onclick="switchView('settings')">
        <div class="user-avatar">Y</div>
        <div class="user-info">
          <div class="user-name">Yash Dodani</div>
          <div class="user-role">Developer</div>
        </div>
      </div>
    </header>

    <!-- 1. DASHBOARD VIEW -->
    <main id="view-dashboard" class="view-container active">
      <div class="dashboard-hero">
        <div>
          <h1 class="hero-title">AI-Powered <span>CI/CD Log Analyzer</span></h1>
          <p class="hero-sub">Upload or paste your CI/CD logs and get instant AI-powered analysis, root cause detection, and actionable solutions.</p>
          <div class="hero-actions">
            <button class="btn-primary" onclick="switchView('analyze')">
              <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><line x1="12" y1="19" x2="12" y2="5"></line><polyline points="5 12 12 5 19 12"></polyline></svg>
              Analyze New Log →
            </button>
            <button class="btn-outline" onclick="switchView('history')">
              <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
              View History
            </button>
          </div>
        </div>
        <div class="hero-illustration-box">
          <img src="/assets/ottie/working 1.png" class="hero-mascot" alt="AI Agent Working">
        </div>
      </div>

      <!-- 4 STATS -->
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-card-title">Total Analyses</div>
          <div class="stat-val-row">
            <div class="stat-number" id="dashTotalAnalyses">24</div>
            <div class="stat-icon" style="background:rgba(99,102,241,0.15); color:#818cf8;">📈</div>
          </div>
          <div class="stat-trend green">+12% from last month</div>
        </div>

        <div class="stat-card">
          <div class="stat-card-title">Success Rate</div>
          <div class="stat-val-row">
            <div class="stat-number">78%</div>
            <div class="stat-icon" style="background:rgba(16,185,129,0.15); color:#34d399;">✓</div>
          </div>
          <div class="stat-trend green">+5% improvement</div>
        </div>

        <div class="stat-card">
          <div class="stat-card-title">Critical Issues</div>
          <div class="stat-val-row">
            <div class="stat-number" style="color:#f87171;">6</div>
            <div class="stat-icon" style="background:rgba(239,68,68,0.15); color:#f87171;">⚠️</div>
          </div>
          <div class="stat-trend red">Needs attention</div>
        </div>

        <div class="stat-card">
          <div class="stat-card-title">Avg. Analysis Time</div>
          <div class="stat-val-row">
            <div class="stat-number">12s</div>
            <div class="stat-icon" style="background:rgba(59,130,246,0.15); color:#60a5fa;">⚡</div>
          </div>
          <div class="stat-trend green">-40% faster</div>
        </div>
      </div>

      <!-- RECENT ANALYSES -->
      <div class="section-card">
        <div class="section-header">
          <div class="section-title">Recent Analyses</div>
          <div class="section-link" onclick="switchView('history')">View all →</div>
        </div>
        <div class="analysis-list" id="dashboardRecentList">
          <!-- Populated by JS -->
        </div>
      </div>
    </main>

    <!-- 2. ANALYZE LOGS VIEW -->
    <main id="view-analyze" class="view-container">
      <div class="page-header">
        <div class="page-title">
          <span style="display:inline-flex; width:28px; height:28px; border-radius:8px; background:linear-gradient(135deg,#6366f1,#8b5cf6); align-items:center; justify-content:center; font-size:14px;">⚡</span>
          Analyze Logs
        </div>
        <div class="page-sub">Paste your CI/CD logs or upload a file to get AI-powered analysis.</div>
      </div>

      <div class="analyze-tabs-bar">
        <button class="analyze-subtab active" onclick="switchAnalyzeSubtab('paste')">📋 Paste Logs</button>
        <button class="analyze-subtab" onclick="switchAnalyzeSubtab('upload')">📁 Upload File</button>
        <button class="analyze-subtab" onclick="switchAnalyzeSubtab('github')">🐙 GitHub Integration</button>
        <button class="analyze-subtab" onclick="switchAnalyzeSubtab('examples')">📝 Example Logs</button>
      </div>

      <!-- SUBTAB: GITHUB INTEGRATION -->
      <div id="subtab-github" style="display:none; margin-bottom:16px;">
        <div class="github-connect-box">
          <input type="text" id="ghTarget" class="input-field" placeholder="Enter GitHub User/Org or Repository (e.g. Yash-Dodani, CI-CD-Log-Analyzer)..." value="Yash-Dodani">
          <button class="btn-primary" onclick="loadGhRepos()">
            <span>Load Repositories</span>
          </button>
        </div>
        <div id="ghReposOutput" style="display:grid; grid-template-columns:repeat(auto-fill, minmax(280px, 1fr)); gap:12px; max-height:260px; overflow-y:auto;">
          <!-- Repos -->
        </div>
      </div>

      <!-- SUBTAB: EXAMPLES -->
      <div id="subtab-examples" style="display:none; margin-bottom:16px; gap:8px;">
        <div style="display:flex; gap:8px; flex-wrap:wrap;">
          <button class="btn-outline" style="padding:6px 12px; font-size:12px;" onclick="loadPreset('pytest')">Pytest Auth Error (Screenshot)</button>
          <button class="btn-outline" style="padding:6px 12px; font-size:12px;" onclick="loadPreset('requests')">Python ModuleNotFoundError</button>
          <button class="btn-outline" style="padding:6px 12px; font-size:12px;" onclick="loadPreset('flutter')">Flutter Null Safety</button>
          <button class="btn-outline" style="padding:6px 12px; font-size:12px;" onclick="loadPreset('docker')">Docker Psycopg2 Fail</button>
          <button class="btn-outline" style="padding:6px 12px; font-size:12px;" onclick="loadPreset('webpack')">Node.js Webpack Fail</button>
        </div>
      </div>

      <!-- CODE TERMINAL EDITOR -->
      <div class="editor-wrapper">
        <textarea id="logEditor" class="editor-textarea" placeholder="Paste your CI/CD error trace, stack trace, or build dump here..."></textarea>
        <div class="editor-footer">
          <span id="charCounter">0 characters</span>
          <button class="clear-btn" onclick="clearLogEditor()">🗑️ Clear</button>
        </div>
      </div>

      <!-- COLLAPSIBLE ADVANCED -->
      <details style="margin-bottom:16px; font-size:12px; color:var(--text-muted);">
        <summary style="cursor:pointer; font-weight:600;">⚙️ Advanced Options (Model: OpenRouter Llama 3.3 / Groq / Gemini)</summary>
        <div style="background:var(--card-bg); padding:14px; border-radius:var(--radius-sm); margin-top:10px; display:flex; gap:12px;">
          <select id="analyzerProviderSelect" class="input-field" style="max-width:300px;">
            <option value="openrouter">🌐 OpenRouter Free Llama 3.3 (Recommended)</option>
            <option value="groq">⚡ Groq Llama 3.3 (Sub-second)</option>
            <option value="gemini">🧠 Google Gemini 1.5 Flash</option>
            <option value="offline">🚀 Offline Smart Heuristics (0 API Key)</option>
          </select>
        </div>
      </details>

      <button class="btn-primary btn-full" id="analyzeExecuteBtn" onclick="executeLogAnalysis()">
        <span id="analyzeBtnIcon">✨</span>
        <span id="analyzeBtnText">Analyze Logs with AI →</span>
      </button>
    </main>

    <!-- 3. ANALYSIS RESULTS VIEW -->
    <main id="view-results" class="view-container">
      <div class="results-top-actions">
        <div class="back-btn" onclick="switchView('analyze')">
          ← Back to Analyze
        </div>
        <div style="display:flex; gap:10px;">
          <button class="btn-outline" onclick="viewRawLogModal()">👁️ View Raw Log</button>
          <button class="btn-primary" onclick="downloadReportJSON()">⬇️ Download Report</button>
        </div>
      </div>

      <!-- ALERT BANNER -->
      <div class="alert-banner">
        <div class="alert-left">
          <div class="alert-icon-box">⚠️</div>
          <div>
            <div class="alert-title" id="resAlertTitle">Test Failure - Authentication Error</div>
            <div class="alert-sub" id="resAlertSub">The tests are failing due to an authentication issue. The API is returning 401 Unauthorized instead of the expected 200 OK status.</div>
          </div>
        </div>
        <div class="alert-badges">
          <span class="badge-pill High" id="resSeverityBadge">High Severity</span>
          <span class="badge-pill" style="background:#1e293b; color:#94a3b8;" id="resConfidenceBadge">Confidence: 0.89</span>
        </div>
      </div>

      <!-- TABS -->
      <div class="result-nav-tabs">
        <button class="res-tab active" onclick="switchResTab('overview')">Overview</button>
        <button class="res-tab" onclick="switchResTab('fixes')">Suggested Fixes</button>
        <button class="res-tab" onclick="switchResTab('prompt')">Cursor / Copilot Prompt</button>
      </div>

      <!-- 4 QUICK INSIGHT CARDS -->
      <div class="insights-grid">
        <div class="insight-card">
          <div class="insight-icon-box" style="background:var(--danger-bg); color:#f87171;">✕</div>
          <div>
            <div class="insight-label">Root Cause</div>
            <div class="insight-val" id="resRootCauseShort">Invalid authentication</div>
          </div>
        </div>

        <div class="insight-card">
          <div class="insight-icon-box" style="background:rgba(99,102,241,0.15); color:#818cf8;">🏷️</div>
          <div>
            <div class="insight-label">Error Category</div>
            <div class="insight-val" id="resCategoryVal">Authentication Error</div>
          </div>
        </div>

        <div class="insight-card">
          <div class="insight-icon-box" style="background:var(--warning-bg); color:#fbbf24;">🧪</div>
          <div>
            <div class="insight-label">Affected Tests</div>
            <div class="insight-val" id="resAffectedTests">1 test failed</div>
          </div>
        </div>

        <div class="insight-card">
          <div class="insight-icon-box" style="background:var(--success-bg); color:#34d399;">⏱️</div>
          <div>
            <div class="insight-label">Estimated Fix Time</div>
            <div class="insight-val" id="resFixTime">5 - 10 minutes</div>
          </div>
        </div>
      </div>

      <!-- SPLIT DETAILS -->
      <div class="detail-grid">
        <!-- LEFT COLUMN -->
        <div>
          <div class="detail-box">
            <div class="detail-box-title">
              <span>📄 Summary</span>
            </div>
            <p id="resSummaryText" style="font-size:13px; color:#cbd5e1; line-height:1.6;"></p>
          </div>

          <div class="detail-box">
            <div class="detail-box-title">
              <span>🔍 Relevant Log Lines</span>
              <button class="btn-outline" style="padding:2px 8px; font-size:11px;" onclick="copyCode('resLogLinesCode')">Copy</button>
            </div>
            <div class="code-display" id="resLogLinesCode"></div>
          </div>

          <!-- DIRECT FIX PROMPT FOR CURSOR / COPILOT -->
          <div class="detail-box" style="border-color:rgba(99, 102, 241, 0.4);">
            <div class="detail-box-title">
              <span style="color:#818cf8;">⚡ AI Prompt for Cursor / GitHub Copilot</span>
              <button class="btn-primary" style="padding:3px 10px; font-size:11px;" onclick="copyPrompt()">Copy Prompt</button>
            </div>
            <div class="code-display" id="resPromptBox" style="color:#e2e8f0; font-family:'Plus Jakarta Sans'; font-size:13px;"></div>
          </div>
        </div>

        <!-- RIGHT COLUMN: AI SUGGESTIONS -->
        <div>
          <div class="detail-box">
            <div class="detail-box-title">
              <div style="display:flex; align-items:center; gap:8px;">
                <img src="/assets/ottie/idea 1.png" style="width:24px; height:24px; object-fit:contain;" alt="Idea">
                <span>AI Suggestions</span>
              </div>
            </div>
            <div id="resSuggestionsList">
              <!-- Populated by JS -->
            </div>
          </div>

          <div class="detail-box">
            <div class="detail-box-title">
              <span>🛠️ Step-by-Step Fix Action Plan</span>
            </div>
            <div id="resStepsList" style="font-size:12px; color:#cbd5e1; line-height:1.7;">
              <!-- Populated by JS -->
            </div>
          </div>
        </div>
      </div>
    </main>

    <!-- 4. HISTORY VIEW -->
    <main id="view-history" class="view-container">
      <div class="page-header">
        <div class="page-title">Analysis History</div>
        <div class="page-sub">View and manage your previous log analyses.</div>
      </div>

      <div class="section-card">
        <div style="display:flex; gap:12px; margin-bottom:16px;">
          <input type="text" id="historySearchInput" class="input-field" placeholder="Search analyses..." oninput="filterHistory()">
          <select id="historyStatusFilter" class="input-field" style="max-width:140px;" onchange="filterHistory()">
            <option value="ALL">All Status</option>
            <option value="High">High</option>
            <option value="Success">Success</option>
            <option value="Medium">Medium</option>
            <option value="Critical">Critical</option>
          </select>
        </div>

        <div class="analysis-list" id="fullHistoryList">
          <!-- Populated by JS -->
        </div>
      </div>
    </main>

    <!-- 5. INTEGRATIONS VIEW -->
    <main id="view-integrations" class="view-container">
      <div class="page-header">
        <div class="page-title">Integrations</div>
        <div class="page-sub">Connect your CI/CD providers and code repositories.</div>
      </div>

      <div style="display:grid; grid-template-columns:repeat(auto-fill, minmax(300px, 1fr)); gap:16px;">
        <div class="detail-box" style="margin-bottom:0;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <div style="display:flex; gap:10px; align-items:center;">
              <span style="font-size:24px;">🐙</span>
              <div>
                <div style="font-weight:700; color:#fff;">GitHub Actions</div>
                <div style="font-size:11px; color:var(--text-dim);">Public & Private Repositories</div>
              </div>
            </div>
            <span class="badge-pill Success">Connected</span>
          </div>
          <p style="font-size:12px; color:var(--text-muted); margin:12px 0;">Automatically fetch workflow runs and inspect job step failures with 1-click reasoning.</p>
          <button class="btn-outline" style="width:100%; justify-content:center;" onclick="switchView('settings')">Configure Token</button>
        </div>

        <div class="detail-box" style="margin-bottom:0;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <div style="display:flex; gap:10px; align-items:center;">
              <span style="font-size:24px;">🦊</span>
              <div>
                <div style="font-weight:700; color:#fff;">GitLab CI</div>
                <div style="font-size:11px; color:var(--text-dim);">Pipelines & Webhooks</div>
              </div>
            </div>
            <span class="badge-pill" style="background:#1e293b; color:#94a3b8;">Available</span>
          </div>
          <p style="font-size:12px; color:var(--text-muted); margin:12px 0;">Direct log ingestion via GitLab CI/CD webhook dispatch.</p>
          <button class="btn-outline" style="width:100%; justify-content:center;" onclick="alert('GitLab Webhook ready! Send POST to /api/analyze')">View Endpoint</button>
        </div>
      </div>
    </main>

    <!-- 6. SETTINGS VIEW -->
    <main id="view-settings" class="view-container">
      <div class="page-header">
        <div class="page-title">Settings</div>
        <div class="page-sub">Configure your AI model providers and integration preferences.</div>
      </div>

      <div class="section-card" style="max-width:680px;">
        <div class="settings-tabs">
          <button class="res-tab active">AI Provider</button>
          <button class="res-tab" onclick="alert('GitHub Token configured below.')">GitHub</button>
        </div>

        <div style="display:flex; flex-direction:column; gap:16px;">
          <div>
            <label style="font-size:12px; font-weight:700; display:block; margin-bottom:6px;">AI Provider</label>
            <select id="settingsProvider" class="input-field" style="width:100%;">
              <option value="openrouter">🌐 OpenRouter (Llama 3.3 Free)</option>
              <option value="groq">⚡ Groq Llama 3.3 (Fast)</option>
              <option value="gemini">🧠 Google Gemini 1.5 Flash</option>
              <option value="offline">🚀 Offline Smart Heuristic (0 API Key)</option>
            </select>
          </div>

          <div>
            <label style="font-size:12px; font-weight:700; display:block; margin-bottom:6px;">API Key</label>
            <input type="password" id="settingsApiKey" class="input-field" style="width:100%;" placeholder="sk-or-v1-...">
          </div>

          <div>
            <label style="font-size:12px; font-weight:700; display:block; margin-bottom:6px;">GitHub Personal Access Token (PAT)</label>
            <input type="password" id="settingsGhToken" class="input-field" style="width:100%;" placeholder="ghp_... (Unlocks private repos and full Actions logs)">
          </div>

          <div style="margin-top:8px;">
            <button class="btn-primary" onclick="saveSettings()">Save Settings</button>
          </div>
        </div>
      </div>
    </main>

  </div>

  <script>
    // GLOBAL STATE
    let allHistory = [];
    let activeIncident = null;

    const PRESETS = {
      pytest: `tests/test_auth.py:12\ndef test_login():\n    response = client.post("/login", json={"email": "test@example.com"})\n>   assert response.status_code == 200\nE   assert 401 == 200\nE   + where 401 = <Response [401 Unauthorized]>.status_code\n\n1 failed, 11 passed in 1.45s`,
      requests: `Traceback (most recent call last):\n  File "src/api_client.py", line 3, in <module>\n    import requests\nModuleNotFoundError: No module named 'requests'\n\nProcess completed with exit code 1.`,
      flutter: `lib/screens/home_dashboard.dart:47:19: Error: The getter 'userProfile' isn't defined for the class 'AuthState'.\nlib/screens/home_dashboard.dart:58:24: Error: A value of type 'String?' cannot be assigned to a variable of type 'String' because 'String?' is nullable.\nExecution failed for task ':app:compileFlutterBuildRelease'.\nBUILD FAILED in 18s`,
      docker: `#6 7.455 Error: pg_config executable not found.\n#6 7.457 pg_config is required to build psycopg2 from source. Please add the directory containing pg_config to the PATH\n#6 ERROR: process "/bin/sh -c pip install --no-cache-dir -r requirements.txt" did not complete successfully: exit code: 1`,
      webpack: `ERROR in ./src/components/PaymentCheckout.tsx 14:2-31\nModule not found: Error: Can't resolve '@stripe/react-stripe-js' in '/app/src/components'\nnpm error code ELIFECYCLE\nnpm error Exit status 1`
    };

    // VIEW SWITCHER
    function switchView(viewName) {
      document.querySelectorAll('.view-container').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));

      const target = document.getElementById('view-' + viewName);
      if (target) target.classList.add('active');

      const nav = document.getElementById('nav-' + viewName);
      if (nav) nav.classList.add('active');

      if (viewName === 'dashboard') renderDashboardRecent();
      if (viewName === 'history') renderFullHistory();
    }

    function switchAnalyzeSubtab(tabName) {
      document.querySelectorAll('.analyze-subtab').forEach(el => el.classList.remove('active'));
      event.target.classList.add('active');

      document.getElementById('subtab-github').style.display = (tabName === 'github') ? 'block' : 'none';
      document.getElementById('subtab-examples').style.display = (tabName === 'examples') ? 'block' : 'none';
    }

    function loadPreset(key) {
      document.getElementById('logEditor').value = PRESETS[key] || '';
      updateCharCount();
    }

    function clearLogEditor() {
      document.getElementById('logEditor').value = '';
      updateCharCount();
    }

    function updateCharCount() {
      const len = document.getElementById('logEditor').value.length;
      document.getElementById('charCounter').textContent = `${len.toLocaleString()} characters`;
    }
    document.getElementById('logEditor').addEventListener('input', updateCharCount);

    // AI ANALYSIS EXECUTION
    async function executeLogAnalysis() {
      const log = document.getElementById('logEditor').value.trim();
      if (!log) {
        alert('Please enter or select a CI/CD log to analyze.');
        return;
      }

      const provider = document.getElementById('analyzerProviderSelect').value;
      const apiKey = localStorage.getItem('ls_api_key') || '';
      const btnIcon = document.getElementById('analyzeBtnIcon');
      const btnText = document.getElementById('analyzeBtnText');

      btnIcon.textContent = '⏳';
      btnText.textContent = 'Analyzing with AI...';

      try {
        const resp = await fetch('/api/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ log, provider, apiKey })
        });
        const data = await resp.json();

        // Build incident object
        activeIncident = {
          id: 'inc-' + Date.now(),
          title: data.category || 'Pipeline Diagnostic Exception',
          category: data.category || 'Build Exception',
          severity: data.severity || 'High',
          time_ago: 'Just now',
          timestamp: new Date().toISOString(),
          env_info: 'Manual trace • CI Runner',
          confidence: data.confidence || '0.95',
          root_cause: data.root_cause || 'Process failed with non-zero exit code.',
          summary: data.root_cause || 'Unhandled runtime exception during execution.',
          relevant_lines: log.slice(0, 300),
          affected_tests: 'Identified trace failures',
          estimated_fix_time: '5 - 10 minutes',
          ai_suggestions: [
            {"title": "Review Root Cause", "desc": data.root_cause},
            {"title": "Implement Recommended Patch", "desc": "Apply the suggested code patch below."},
            {"title": "Prevention Guideline", "desc": data.prevention || "Configure pre-commit test hooks."}
          ],
          fix_prompt: `Fix CI/CD error: ${data.root_cause}\nCategory: ${data.category}\nSuggested Fix: ${data.suggested_fix}`,
          fix_steps: (data.suggested_fix || '').split('\n').filter(l => l.trim().length > 0)
        };

        // Save to server history
        await fetch('/api/history', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(activeIncident)
        });

        // Add to local state
        allHistory.unshift(activeIncident);

        // Open Results View
        renderResultsView(activeIncident);
        switchView('results');

      } catch (err) {
        alert('Analysis error: ' + err);
      } finally {
        btnIcon.textContent = '✨';
        btnText.textContent = 'Analyze Logs with AI →';
      }
    }

    // RENDER RESULTS VIEW
    function renderResultsView(inc) {
      activeIncident = inc;
      document.getElementById('resAlertTitle').textContent = inc.title || 'Pipeline Error';
      document.getElementById('resAlertSub').textContent = inc.summary || inc.root_cause;
      document.getElementById('resSeverityBadge').textContent = (inc.severity || 'High') + ' Severity';
      document.getElementById('resSeverityBadge').className = 'badge-pill ' + (inc.severity || 'High');
      document.getElementById('resConfidenceBadge').textContent = 'Confidence: ' + (inc.confidence || '0.90');

      document.getElementById('resRootCauseShort').textContent = (inc.root_cause || '').slice(0, 32) + '...';
      document.getElementById('resCategoryVal').textContent = inc.category || 'Error';
      document.getElementById('resAffectedTests').textContent = inc.affected_tests || '1 failed';
      document.getElementById('resFixTime').textContent = inc.estimated_fix_time || '5m';

      document.getElementById('resSummaryText').textContent = inc.summary || inc.root_cause;
      document.getElementById('resLogLinesCode').textContent = inc.relevant_lines || '';
      document.getElementById('resPromptBox').textContent = inc.fix_prompt || 'Fix the error identified above.';

      // Render Suggestions
      const suggBox = document.getElementById('resSuggestionsList');
      suggBox.innerHTML = (inc.ai_suggestions || []).map((s, idx) => `
        <div class="suggestion-item">
          <div class="suggestion-num">${idx + 1}</div>
          <div>
            <div class="suggestion-title">${s.title}</div>
            <div class="suggestion-desc">${s.desc}</div>
          </div>
        </div>
      `).join('');

      // Render Steps
      const stepsBox = document.getElementById('resStepsList');
      stepsBox.innerHTML = (inc.fix_steps || []).map(step => `
        <div style="padding:6px 0; display:flex; gap:8px;">
          <span style="color:#818cf8;">✓</span>
          <span>${step}</span>
        </div>
      `).join('');
    }

    function switchResTab(tab) {
      document.querySelectorAll('.res-tab').forEach(el => el.classList.remove('active'));
      event.target.classList.add('active');
    }

    function copyCode(id) {
      navigator.clipboard.writeText(document.getElementById(id).textContent);
      alert('Copied to clipboard!');
    }

    function copyPrompt() {
      navigator.clipboard.writeText(document.getElementById('resPromptBox').textContent);
      alert('AI Fix Prompt copied! Paste into Cursor or Copilot to fix automatically.');
    }

    function downloadReportJSON() {
      if (!activeIncident) return;
      const blob = new Blob([JSON.stringify(activeIncident, null, 2)], { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `ci_cd_analysis_${Date.now()}.json`;
      a.click();
    }

    function viewRawLogModal() {
      if (!activeIncident) return;
      alert("RAW CI/CD LOG:\n\n" + activeIncident.relevant_lines);
    }

    // RENDER DASHBOARD RECENT
    function renderDashboardRecent() {
      const list = document.getElementById('dashboardRecentList');
      list.innerHTML = allHistory.slice(0, 3).map(inc => {
        const isSuccess = inc.severity === 'Success';
        return `
          <div class="analysis-item" onclick='openIncident("${inc.id}")'>
            <div class="item-left">
              <div class="status-circle ${isSuccess ? 'success' : 'error'}">
                ${isSuccess ? '✓' : '✕'}
              </div>
              <div>
                <div class="item-title">${inc.title}</div>
                <div class="item-sub">${inc.env_info || 'Python • GitHub Actions'}</div>
              </div>
            </div>
            <div class="item-right">
              <span class="badge-pill ${inc.severity}">${inc.severity}</span>
              <span style="font-size:11px; color:var(--text-dim);">${inc.time_ago || 'Recent'}</span>
            </div>
          </div>
        `;
      }).join('');
      document.getElementById('dashTotalAnalyses').textContent = allHistory.length;
    }

    // RENDER FULL HISTORY
    function renderFullHistory() {
      const list = document.getElementById('fullHistoryList');
      const q = (document.getElementById('historySearchInput')?.value || '').toLowerCase();
      const statusFilter = document.getElementById('historyStatusFilter')?.value || 'ALL';

      const filtered = allHistory.filter(h => {
        const matchQ = (h.title + h.summary + h.category).toLowerCase().includes(q);
        const matchStatus = (statusFilter === 'ALL') || (h.severity === statusFilter);
        return matchQ && matchStatus;
      });

      if (filtered.length === 0) {
        list.innerHTML = '<div style="color:var(--text-dim); font-size:13px; text-align:center; padding:30px;">No analyses found matching filter.</div>';
        return;
      }

      list.innerHTML = filtered.map(inc => {
        const isSuccess = inc.severity === 'Success';
        return `
          <div class="analysis-item" onclick='openIncident("${inc.id}")'>
            <div class="item-left">
              <div class="status-circle ${isSuccess ? 'success' : 'error'}">
                ${isSuccess ? '✓' : '✕'}
              </div>
              <div>
                <div class="item-title">${inc.title}</div>
                <div class="item-sub">${inc.env_info || ''}</div>
              </div>
            </div>
            <div class="item-right">
              <span class="badge-pill ${inc.severity}">${inc.severity}</span>
              <span style="font-size:13px; color:var(--text-dim);">›</span>
            </div>
          </div>
        `;
      }).join('');
    }

    function filterHistory() {
      renderFullHistory();
    }

    function openIncident(id) {
      const found = allHistory.find(h => h.id === id);
      if (found) {
        renderResultsView(found);
        switchView('results');
      }
    }

    // GITHUB INTEGRATION
    async function loadGhRepos() {
      const target = document.getElementById('ghTarget').value.trim();
      const token = localStorage.getItem('ls_gh_token') || '';
      const output = document.getElementById('ghReposOutput');

      output.innerHTML = '<div style="color:var(--text-muted); font-size:12px; padding:10px;">Loading GitHub repositories...</div>';

      try {
        const resp = await fetch('/api/github/repos', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token, username: target })
        });
        const repos = await resp.json();

        if (repos.error) {
          output.innerHTML = `<div style="color:#f87171; font-size:12px;">Error: ${repos.error}</div>`;
          return;
        }

        output.innerHTML = repos.map(r => `
          <div class="stat-card" style="cursor:pointer;" onclick='loadRepoRuns("${r.owner.login}", "${r.name}")'>
            <div style="font-weight:700; font-size:13px; color:#fff;">${r.name}</div>
            <div style="font-size:11px; color:var(--text-dim); margin-top:4px;">${r.private ? '🔒 Private' : '🌐 Public'} • ${r.default_branch}</div>
          </div>
        `).join('');
      } catch (err) {
        output.innerHTML = `<div style="color:#f87171; font-size:12px;">Could not fetch repos: ${err}</div>`;
      }
    }

    async function loadRepoRuns(owner, repo) {
      const token = localStorage.getItem('ls_gh_token') || '';
      const output = document.getElementById('ghReposOutput');
      output.innerHTML = `<div style="color:var(--text-muted); font-size:12px;">Fetching workflow runs for ${owner}/${repo}...</div>`;

      try {
        const resp = await fetch('/api/github/runs', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ owner, repo, token })
        });
        const runs = await resp.json();

        if (runs.length === 0) {
          output.innerHTML = `<div style="color:var(--text-dim); font-size:12px;">No workflow runs found for ${owner}/${repo}.</div>`;
          return;
        }

        output.innerHTML = runs.map(run => `
          <div class="stat-card" style="cursor:pointer; display:flex; justify-content:space-between; align-items:center;" onclick='pullRunLog("${owner}", "${repo}", ${run.id})'>
            <div>
              <div style="font-weight:700; font-size:13px; color:#fff;">${run.name || 'CI/CD'}</div>
              <div style="font-size:11px; color:var(--text-dim);">${run.head_branch} • ${run.author}</div>
            </div>
            <span class="badge-pill ${run.conclusion === 'success' ? 'Success' : 'High'}">${run.conclusion || run.status}</span>
          </div>
        `).join('');
      } catch (err) {
        output.innerHTML = `<div style="color:#f87171; font-size:12px;">Error: ${err}</div>`;
      }
    }

    async function pullRunLog(owner, repo, runId) {
      const token = localStorage.getItem('ls_gh_token') || '';
      try {
        const resp = await fetch('/api/github/jobs', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ owner, repo, runId, token })
        });
        const jobs = await resp.json();
        const failedJob = jobs.find(j => j.conclusion === 'failure') || jobs[0];

        if (failedJob) {
          const logResp = await fetch('/api/github/logs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ owner, repo, jobId: failedJob.id, token })
          });
          const logData = await logResp.json();
          document.getElementById('logEditor').value = logData.log || `Workflow Job ${failedJob.name} failed.`;
          updateCharCount();
          executeLogAnalysis();
        }
      } catch (err) {
        alert('Could not fetch log: ' + err);
      }
    }

    // SETTINGS MANAGEMENT
    function loadSettings() {
      const key = localStorage.getItem('ls_api_key') || '';
      const ghToken = localStorage.getItem('ls_gh_token') || '';
      document.getElementById('settingsApiKey').value = key;
      document.getElementById('settingsGhToken').value = ghToken;
    }

    function saveSettings() {
      const key = document.getElementById('settingsApiKey').value.trim();
      const ghToken = document.getElementById('settingsGhToken').value.trim();
      localStorage.setItem('ls_api_key', key);
      localStorage.setItem('ls_gh_token', ghToken);
      alert('Settings saved successfully!');
    }

    function handleSearchKey(e) {
      if (e.key === 'Enter') {
        const q = e.target.value;
        switchView('history');
        document.getElementById('historySearchInput').value = q;
        filterHistory();
      }
    }

    document.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        document.getElementById('globalSearch').focus();
      }
    });

    // BOOTSTRAP
    window.onload = async () => {
      loadSettings();
      loadPreset('pytest');
      try {
        const resp = await fetch('/api/history');
        allHistory = await resp.json();
      } catch (e) {
        allHistory = [];
      }
      renderDashboardRecent();
    };
  </script>
</body>
</html>
'''

class RequestHandler(BaseHTTPRequestHandler):
    def send_json_response(self, status: int, data: Any):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        # Serve static assets (such as ottie images)
        if self.path.startswith("/assets/"):
            clean_path = urllib.parse.unquote(self.path.split("?")[0])
            rel_path = clean_path.lstrip("/").replace("/", os.sep)
            file_path = os.path.join(BASE_DIR, rel_path)
            if os.path.exists(file_path) and os.path.isfile(file_path):
                mime, _ = mimetypes.guess_type(file_path)
                self.send_response(200)
                self.send_header("Content-Type", mime or "application/octet-stream")
                self.send_header("Cache-Control", "public, max-age=86400")
                self.end_headers()
                with open(file_path, "rb") as f:
                    self.wfile.write(f.read())
                return
            else:
                self.send_error(404, "Asset Not Found")
                return

        if self.path in ["/", "/index.html", "/dashboard", "/analyze"]:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_DASHBOARD.encode("utf-8"))
        elif self.path == "/api/history":
            self.send_json_response(200, load_history())
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        try:
            data = json.loads(body)
        except Exception:
            data = {}

        # 1. AI LOG ANALYZE
        if self.path == "/api/analyze":
            raw_log = data.get("log", "")
            provider = data.get("provider", "openrouter")
            api_key = data.get("apiKey") or DEFAULT_OPENROUTER_KEY

            windowed = analyzer.sanitize_and_extract_error_window(raw_log)
            result = None

            if provider == "openrouter":
                result = analyzer.call_openrouter_api(api_key, windowed)
            elif provider == "groq":
                result = analyzer.call_groq_api(api_key, windowed)
            elif provider == "gemini":
                result = analyzer.call_gemini_api(api_key, windowed)

            if not result:
                result = analyzer.run_offline_heuristics(windowed)

            self.send_json_response(200, result)

        # 2. GITHUB REPOSITORIES
        elif self.path == "/api/github/repos":
            token = data.get("token") or None
            username = data.get("username") or "Yash-Dodani"
            try:
                repos = analyzer.fetch_github_repos(token=token, username=username)
                self.send_json_response(200, repos)
            except Exception as e:
                self.send_json_response(400, {"error": str(e)})

        # 3. GITHUB WORKFLOW RUNS
        elif self.path == "/api/github/runs":
            owner = data.get("owner", "")
            repo = data.get("repo", "")
            token = data.get("token") or None
            try:
                runs = analyzer.fetch_workflow_runs(owner, repo, token=token)
                self.send_json_response(200, runs)
            except Exception as e:
                self.send_json_response(400, {"error": str(e)})

        # 4. GITHUB RUN JOBS
        elif self.path == "/api/github/jobs":
            owner = data.get("owner", "")
            repo = data.get("repo", "")
            run_id = data.get("runId")
            token = data.get("token") or None
            try:
                jobs = analyzer.fetch_run_jobs(owner, repo, run_id, token=token)
                self.send_json_response(200, jobs)
            except Exception as e:
                self.send_json_response(400, {"error": str(e)})

        # 5. GITHUB JOB LOGS
        elif self.path == "/api/github/logs":
            owner = data.get("owner", "")
            repo = data.get("repo", "")
            job_id = data.get("jobId")
            token = data.get("token") or None
            try:
                log_text = analyzer.fetch_job_logs(owner, repo, job_id, token=token)
                self.send_json_response(200, {"log": log_text})
            except Exception as e:
                self.send_json_response(400, {"error": str(e)})

        # 6. INCIDENT HISTORY LOGGING
        elif self.path == "/api/history":
            save_history(data)
            self.send_json_response(200, {"status": "success"})

        else:
            self.send_error(404, "Not Found")


def run():
    server = HTTPServer(("0.0.0.0", PORT), RequestHandler)
    print(f"[*] CI Log Analyzer running at http://localhost:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")


if __name__ == "__main__":
    run()
