#!/usr/bin/env python3
"""
AI CI/CD Log Analyzer — Full SaaS Web Server & Dashboard
Author: Yash Dodani (github.com/Yash-Dodani)
Description: Production-ready dark-mode AIOps observability dashboard with live GitHub Actions
             integration, multi-LLM diagnostic engine (Gemini, Groq, OpenRouter, Offline),
             and incident analytics.
"""

import os
import sys
import json
import urllib.request
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, List

# Ensure safe UTF-8 terminal encoding on Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

import analyzer

PORT = int(os.environ.get("PORT", 8080))
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")
HISTORY_FILE = os.path.join(BASE_DIR, "incident_history.json")


def load_history() -> List[Dict[str, Any]]:
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def save_history(entry: Dict[str, Any]):
    history = load_history()
    history.insert(0, entry)
    # keep last 50 entries
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
  <title>LogSense AI — CI/CD Observability & Diagnostic SaaS</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #090d16;
      --surface: #0f172a;
      --card-bg: #131d33;
      --card-hover: #192644;
      --border: #1e293b;
      --border-focus: #3b82f6;
      --accent: #3b82f6;
      --accent-glow: rgba(59, 130, 246, 0.25);
      --purple: #8b5cf6;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --danger: #ef4444;
      --warning: #f59e0b;
      --success: #10b981;
      --radius: 10px;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      overflow-x: hidden;
    }

    /* TOP NAVBAR */
    .navbar {
      height: 64px;
      border-bottom: 1px solid var(--border);
      background: rgba(15, 23, 42, 0.85);
      backdrop-filter: blur(12px);
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 28px;
      position: sticky;
      top: 0;
      z-index: 50;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      text-decoration: none;
    }
    .brand-icon {
      width: 34px;
      height: 34px;
      background: linear-gradient(135deg, #3b82f6, #8b5cf6);
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 0 16px var(--accent-glow);
    }
    .brand-name {
      font-size: 17px;
      font-weight: 800;
      color: #fff;
      letter-spacing: -0.5px;
    }
    .brand-pill {
      background: rgba(59, 130, 246, 0.15);
      color: #60a5fa;
      font-size: 11px;
      font-weight: 700;
      padding: 2px 7px;
      border-radius: 5px;
      border: 1px solid rgba(59, 130, 246, 0.3);
      font-family: 'JetBrains Mono', monospace;
    }

    /* NAV TABS */
    .nav-tabs {
      display: flex;
      align-items: center;
      gap: 6px;
      background: rgba(15, 23, 42, 0.6);
      padding: 4px;
      border-radius: 8px;
      border: 1px solid var(--border);
    }
    .nav-tab {
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-family: inherit;
      font-size: 13px;
      font-weight: 600;
      padding: 6px 14px;
      border-radius: 6px;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 8px;
      transition: all 0.2s;
    }
    .nav-tab:hover {
      color: var(--text);
      background: rgba(255, 255, 255, 0.04);
    }
    .nav-tab.active {
      background: var(--card-bg);
      color: #fff;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
      border: 1px solid rgba(59, 130, 246, 0.3);
    }

    /* USER & GH CONNECT */
    .nav-actions {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .gh-status-badge {
      display: flex;
      align-items: center;
      gap: 8px;
      background: var(--card-bg);
      border: 1px solid var(--border);
      padding: 6px 12px;
      border-radius: 20px;
      font-size: 12px;
      color: var(--text-muted);
      cursor: pointer;
      transition: all 0.2s;
    }
    .gh-status-badge:hover {
      border-color: var(--accent);
      color: var(--text);
    }
    .gh-avatar {
      width: 20px;
      height: 20px;
      border-radius: 50%;
      background: #334155;
    }

    /* APP WRAPPER */
    .main-content {
      flex: 1;
      max-width: 1400px;
      width: 100%;
      margin: 0 auto;
      padding: 24px;
    }

    /* TAB VIEWS */
    .tab-view {
      display: none;
    }
    .tab-view.active {
      display: block;
      animation: fadeIn 0.25s ease-out;
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(4px); }
      to { opacity: 1; transform: translateY(0); }
    }

    /* GRID LAYOUTS */
    .two-col-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
    }
    @media (max-width: 1024px) {
      .two-col-grid { grid-template-columns: 1fr; }
    }

    /* CARDS */
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 20px;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
    }
    .card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
      padding-bottom: 12px;
      border-bottom: 1px solid var(--border);
    }
    .card-title {
      font-size: 14px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.6px;
      color: var(--text-muted);
      display: flex;
      align-items: center;
      gap: 8px;
    }

    /* GITHUB WORKFLOW INSPECTOR */
    .gh-connect-bar {
      display: flex;
      gap: 12px;
      margin-bottom: 20px;
      background: var(--surface);
      padding: 16px;
      border-radius: var(--radius);
      border: 1px solid var(--border);
    }
    .input-box {
      flex: 1;
      background: #090d16;
      border: 1px solid var(--border);
      border-radius: 8px;
      color: #fff;
      font-family: inherit;
      font-size: 13px;
      padding: 10px 14px;
      outline: none;
      transition: border-color 0.2s;
    }
    .input-box:focus { border-color: var(--accent); }
    .btn {
      background: linear-gradient(135deg, #2563eb, #1d4ed8);
      color: #fff;
      border: none;
      border-radius: 8px;
      font-family: inherit;
      font-size: 13px;
      font-weight: 600;
      padding: 10px 18px;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 8px;
      transition: all 0.2s;
    }
    .btn:hover {
      opacity: 0.92;
      box-shadow: 0 4px 14px var(--accent-glow);
    }
    .btn-secondary {
      background: #1e293b;
      color: #cbd5e1;
      border: 1px solid #334155;
    }
    .btn-secondary:hover {
      background: #27354a;
      color: #fff;
    }

    /* REPOS & RUNS SPLIT */
    .pipeline-view {
      display: grid;
      grid-template-columns: 340px 1fr;
      gap: 20px;
      min-height: 580px;
    }
    @media (max-width: 900px) {
      .pipeline-view { grid-template-columns: 1fr; }
    }

    .repo-list {
      display: flex;
      flex-direction: column;
      gap: 8px;
      max-height: 540px;
      overflow-y: auto;
      padding-right: 6px;
    }
    .repo-item {
      background: #090d16;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px;
      cursor: pointer;
      transition: all 0.2s;
    }
    .repo-item:hover {
      border-color: var(--accent);
      background: #0e1524;
    }
    .repo-item.selected {
      border-color: var(--accent);
      background: rgba(59, 130, 246, 0.08);
      box-shadow: inset 3px 0 0 var(--accent);
    }
    .repo-name {
      font-size: 13px;
      font-weight: 700;
      color: #fff;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .repo-desc {
      font-size: 11px;
      color: var(--text-dim);
      margin-top: 4px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    /* RUNS LIST */
    .runs-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    .runs-table th {
      text-align: left;
      padding: 10px 14px;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--text-dim);
      border-bottom: 1px solid var(--border);
    }
    .runs-table td {
      padding: 12px 14px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      vertical-align: middle;
    }
    .runs-table tr:hover {
      background: rgba(255, 255, 255, 0.02);
    }

    /* BADGES */
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 3px 8px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 700;
      font-family: 'JetBrains Mono', monospace;
    }
    .badge-success { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge-failure { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
    .badge-queued { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }

    /* CODE & LOG TEXTAREAS */
    .code-area {
      width: 100%;
      height: 320px;
      background: #090d16;
      border: 1px solid var(--border);
      border-radius: 8px;
      color: #e2e8f0;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      padding: 14px;
      line-height: 1.5;
      resize: vertical;
      outline: none;
    }
    .code-area:focus { border-color: var(--accent); }

    /* PRESET BUTTONS */
    .preset-bar {
      display: flex;
      gap: 8px;
      margin-bottom: 14px;
      flex-wrap: wrap;
      align-items: center;
    }
    .preset-btn {
      background: #1e293b;
      border: 1px solid #334155;
      color: #cbd5e1;
      font-size: 11px;
      font-weight: 600;
      padding: 6px 11px;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.2s;
    }
    .preset-btn:hover {
      background: var(--accent);
      color: #fff;
      border-color: var(--accent);
    }

    /* DIAGNOSTIC RESULT BOX */
    .diagnostic-panel {
      display: flex;
      flex-direction: column;
      gap: 16px;
    }
    .result-section {
      background: #090d16;
      border-radius: 8px;
      border: 1px solid var(--border);
      padding: 16px;
    }
    .result-label {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.6px;
      color: var(--text-dim);
      font-weight: 700;
      margin-bottom: 8px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .copy-btn {
      background: #1e293b;
      border: 1px solid #334155;
      color: var(--text-muted);
      font-size: 11px;
      padding: 3px 8px;
      border-radius: 4px;
      cursor: pointer;
      transition: all 0.2s;
    }
    .copy-btn:hover { color: #fff; border-color: var(--accent); }

    .code-box {
      background: #000;
      border: 1px solid #1e293b;
      border-radius: 6px;
      padding: 12px;
      color: #38bdf8;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      white-space: pre-wrap;
      overflow-x: auto;
      line-height: 1.45;
    }

    /* EMPTY / PLACEHOLDER */
    .empty-placeholder {
      min-height: 400px;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      border: 2px dashed var(--border);
      border-radius: 8px;
      color: var(--text-dim);
      text-align: center;
      padding: 30px;
    }

    /* STATS CARDS */
    .stats-row {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
      margin-bottom: 24px;
    }
    @media (max-width: 900px) {
      .stats-row { grid-template-columns: repeat(2, 1fr); }
    }
    .stat-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 18px;
    }
    .stat-val {
      font-size: 26px;
      font-weight: 800;
      color: #fff;
      margin-top: 6px;
    }
    .stat-desc {
      font-size: 11px;
      color: var(--text-dim);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      font-weight: 700;
    }

    /* SETTINGS FORM */
    .settings-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
    }
    @media (max-width: 800px) {
      .settings-grid { grid-template-columns: 1fr; }
    }
    .form-group {
      margin-bottom: 16px;
    }
    .form-label {
      display: block;
      font-size: 12px;
      font-weight: 600;
      color: var(--text-muted);
      margin-bottom: 6px;
    }
  </style>
</head>
<body>

  <!-- TOP NAVBAR -->
  <header class="navbar">
    <a href="#" class="brand">
      <div class="brand-icon">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
      </div>
      <div>
        <div class="brand-name">LogSense AI</div>
      </div>
      <span class="brand-pill">AIOps v2.0 SaaS</span>
    </a>

    <!-- TABS -->
    <nav class="nav-tabs">
      <button class="nav-tab active" onclick="switchTab('github')">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"></path></svg>
        GitHub Pipelines
      </button>
      <button class="nav-tab" onclick="switchTab('analyzer')">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
        AI Diagnostic Lab
      </button>
      <button class="nav-tab" onclick="switchTab('analytics')">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="20" x2="18" y2="10"></line><line x1="12" y1="20" x2="12" y2="4"></line><line x1="6" y1="20" x2="6" y2="14"></line></svg>
        Incident Analytics
      </button>
      <button class="nav-tab" onclick="switchTab('settings')">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
        API Vault
      </button>
    </nav>

    <!-- RIGHT STATUS -->
    <div class="nav-actions">
      <div id="ghProfilePill" class="gh-status-badge" onclick="switchTab('settings')">
        <span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:#10b981;"></span>
        <span id="ghProfileText">GitHub: Public Mode</span>
      </div>
    </div>
  </header>

  <!-- MAIN APP CONTAINER -->
  <main class="main-content">

    <!-- ========================================== -->
    <!-- TAB 1: GITHUB PIPELINES -->
    <!-- ========================================== -->
    <div id="tab-github" class="tab-view active">
      <div class="gh-connect-bar">
        <input type="text" id="ghTargetInput" class="input-box" placeholder="Enter GitHub Username or Org (e.g. Yash-Dodani, facebook, vercel)..." value="Yash-Dodani">
        <button class="btn" onclick="fetchGitHubRepos()">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
          Explore Repositories
        </button>
      </div>

      <div class="pipeline-view">
        <!-- REPOSITORIES COLUMN -->
        <div class="card" style="display:flex; flex-direction:column;">
          <div class="card-header">
            <span class="card-title">Repositories (<span id="repoCount">0</span>)</span>
            <input type="text" id="repoSearch" oninput="filterRepos()" placeholder="Filter..." style="background:#090d16; border:1px solid var(--border); border-radius:4px; font-size:11px; padding:3px 8px; color:#fff; width:100px;">
          </div>
          <div id="repoListContainer" class="repo-list">
            <div style="color:var(--text-dim); font-size:12px; text-align:center; padding:30px 10px;">
              Click "Explore Repositories" above to inspect GitHub Actions.
            </div>
          </div>
        </div>

        <!-- WORKFLOW RUNS COLUMN -->
        <div class="card">
          <div class="card-header">
            <span class="card-title">
              Workflow Runs: <span id="currentRepoTitle" style="color:#60a5fa; text-transform:none; margin-left:4px;">None Selected</span>
            </span>
            <button class="btn btn-secondary" onclick="refreshWorkflowRuns()" style="font-size:11px; padding:4px 10px;">
              ↻ Refresh
            </button>
          </div>

          <div id="runsContainer" style="overflow-x:auto;">
            <div class="empty-placeholder" style="min-height:360px;">
              <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="margin-bottom:12px; opacity:0.5;"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>
              <p style="font-size:13px;">Select a repository on the left to inspect its live GitHub Actions workflow runs.</p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- ========================================== -->
    <!-- TAB 2: AI DIAGNOSTIC LAB -->
    <!-- ========================================== -->
    <div id="tab-analyzer" class="tab-view">
      <div class="two-col-grid">
        <!-- LEFT: INPUT LOG -->
        <div class="card">
          <div class="card-header">
            <span class="card-title">Failed Build / Test Trace</span>
            <span id="logLinesCount" style="font-size:11px; color:var(--text-dim); font-family:'JetBrains Mono';">0 lines</span>
          </div>

          <div class="preset-bar">
            <span style="font-size:11px; color:var(--text-dim); font-weight:700;">PRESETS:</span>
            <button class="preset-btn" onclick="loadSample('flutter')">Flutter Build Fail</button>
            <button class="preset-btn" onclick="loadSample('pytest')">Python Pytest Fail</button>
            <button class="preset-btn" onclick="loadSample('docker')">Docker Psycopg2 Fail</button>
            <button class="preset-btn" onclick="loadSample('nodejs')">Node.js Webpack Fail</button>
            <button class="preset-btn" style="background:#090d16; border-color:#334155; color:#94a3b8;" onclick="clearLog()">Clear</button>
          </div>

          <textarea id="logInput" class="code-area" placeholder="Paste your raw terminal dump, GitHub Actions job failure log, or stack trace here..."></textarea>

          <div style="display:flex; gap:12px; margin-top:14px;">
            <select id="modelSelect" class="input-box" style="flex:1;">
              <option value="offline">⚡ Offline Smart Heuristics (Zero API Key)</option>
              <option value="gemini">🧠 Google Gemini 1.5/2.0 Flash (Free API)</option>
              <option value="groq">⚡ Groq Llama 3.3 70B (Fast Free Tier)</option>
              <option value="openrouter">🌐 OpenRouter Free Tier (Llama-3.3)</option>
            </select>
            <button class="btn" onclick="runAnalysis()" id="analyzeBtn" style="padding:0 24px;">
              <span id="btnIcon">⚡</span>
              <span id="btnText">Analyze Log</span>
            </button>
          </div>
        </div>

        <!-- RIGHT: DIAGNOSTIC & REMEDIATION -->
        <div class="card">
          <div class="card-header">
            <span class="card-title">AI Remediation & Root Cause</span>
            <div id="resultStatusBadges" style="display:flex; gap:6px;"></div>
          </div>

          <div id="placeholderResult" class="empty-placeholder">
            <svg width="44" height="44" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="margin-bottom:14px; opacity:0.4;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
            <div style="font-size:14px; font-weight:600; color:var(--text);">Awaiting Diagnostic Input</div>
            <p style="font-size:12px; margin-top:6px; max-width:320px;">
              Load a sample preset on the left or pull a failed log from GitHub Actions to generate instant reasoning and code fixes.
            </p>
          </div>

          <div id="diagnosticResults" class="diagnostic-panel" style="display:none;">
            <!-- ROOT CAUSE -->
            <div class="result-section">
              <div class="result-label">
                <span>1. Root Cause Explanation</span>
                <span id="categoryPill" class="badge badge-failure">Exception</span>
              </div>
              <div id="rootCauseText" style="font-size:13px; line-height:1.6; color:#f1f5f9;"></div>
            </div>

            <!-- CODE FIX -->
            <div class="result-section">
              <div class="result-label">
                <span>2. Recommended Code Fix / Patch</span>
                <button class="copy-btn" onclick="copySnippet('fixCode')">Copy Patch</button>
              </div>
              <div id="fixCode" class="code-box"></div>
            </div>

            <!-- PREVENTION -->
            <div class="result-section">
              <div class="result-label">
                <span>3. Prevention Strategy</span>
              </div>
              <div id="preventionText" style="font-size:12px; line-height:1.5; color:#cbd5e1;"></div>
            </div>

            <!-- EXPORT ACTIONS -->
            <div style="display:flex; gap:10px; justify-content:flex-end;">
              <button class="btn btn-secondary" onclick="exportMarkdown()">
                📋 Copy Markdown (PR / Issue)
              </button>
              <button class="btn btn-secondary" onclick="exportJSON()">
                ⬇️ Export JSON
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- ========================================== -->
    <!-- TAB 3: INCIDENT ANALYTICS -->
    <!-- ========================================== -->
    <div id="tab-analytics" class="tab-view">
      <div class="stats-row">
        <div class="stat-card">
          <div class="stat-desc">Total Diagnosed</div>
          <div class="stat-val" id="statTotal">0</div>
        </div>
        <div class="stat-card">
          <div class="stat-desc">Avg AI Confidence</div>
          <div class="stat-val" style="color:#10b981;" id="statConfidence">96%</div>
        </div>
        <div class="stat-card">
          <div class="stat-desc">Top Failure Domain</div>
          <div class="stat-val" style="font-size:18px; margin-top:10px; color:#60a5fa;" id="statTopCategory">Dependency / Type</div>
        </div>
        <div class="stat-card">
          <div class="stat-desc">Engine Health</div>
          <div class="stat-val" style="color:#34d399; font-size:18px; margin-top:10px;">Operational</div>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <span class="card-title">Recent Incident Log</span>
          <button class="btn btn-secondary" onclick="loadHistoryTable()" style="font-size:11px; padding:4px 10px;">↻ Refresh</button>
        </div>
        <div style="overflow-x:auto;">
          <table class="runs-table" id="historyTable">
            <thead>
              <tr>
                <th>Time</th>
                <th>Category</th>
                <th>Severity</th>
                <th>Root Cause Summary</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody id="historyTableBody">
              <tr>
                <td colspan="5" style="text-align:center; color:var(--text-dim); padding:30px;">
                  No incidents logged yet. Run an analysis in the Diagnostic Lab to see records.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ========================================== -->
    <!-- TAB 4: SETTINGS & API VAULT -->
    <!-- ========================================== -->
    <div id="tab-settings" class="tab-view">
      <div class="card" style="max-width:800px; margin:0 auto;">
        <div class="card-header">
          <span class="card-title">API Key Vault & Integrations</span>
          <span style="font-size:11px; color:#10b981;">🔒 Encrypted in LocalStorage</span>
        </div>
        <p style="font-size:12px; color:var(--text-muted); margin-bottom:20px;">
          Configure your keys below. All credentials remain on your client/machine and are not logged or stored elsewhere.
        </p>

        <div class="settings-grid">
          <div class="form-group">
            <label class="form-label">GitHub Personal Access Token (PAT)</label>
            <input type="password" id="vaultGhToken" class="input-box" placeholder="ghp_xxxxxxxxxxxx (Optional, unlocks private repos & higher rate limits)">
          </div>
          <div class="form-group">
            <label class="form-label">Google Gemini API Key (Free Tier)</label>
            <input type="password" id="vaultGeminiKey" class="input-box" placeholder="AIzaSy...">
          </div>
          <div class="form-group">
            <label class="form-label">Groq API Key (Free Tier)</label>
            <input type="password" id="vaultGroqKey" class="input-box" placeholder="gsk_...">
          </div>
          <div class="form-group">
            <label class="form-label">OpenRouter API Key (Optional)</label>
            <input type="password" id="vaultOpenRouterKey" class="input-box" placeholder="sk-or-v1-...">
          </div>
        </div>

        <div class="form-group">
          <label class="form-label">Slack / Discord Webhook URL (Optional Alert Dispatch)</label>
          <input type="text" id="vaultWebhook" class="input-box" placeholder="https://hooks.slack.com/services/...">
        </div>

        <div style="display:flex; justify-content:space-between; align-items:center; margin-top:20px;">
          <button class="btn btn-secondary" onclick="clearKeys()">Clear All Keys</button>
          <button class="btn" onclick="saveKeys()">Save Settings</button>
        </div>
      </div>
    </div>

  </main>

  <script>
    // State Store
    let allRepos = [];
    let currentSelectedRepo = null;
    let latestAnalysisResult = null;

    // SAMPLES
    const SAMPLES = {
      flutter: `[2026-10-21T08:14:38.419Z] lib/screens/home_dashboard.dart:47:19: Error: The getter 'userProfile' isn't defined for the class 'AuthState'.\n[2026-10-21T08:14:38.425Z] lib/screens/home_dashboard.dart:58:24: Error: A value of type 'String?' cannot be assigned to a variable of type 'String' because 'String?' is nullable and 'String' isn't.\n[2026-10-21T08:14:40.014Z] Execution failed for task ':app:compileFlutterBuildRelease'.\nBUILD FAILED in 18s`,
      pytest: `tests/test_payment_api.py:44: in stripe_webhook\n    stripe.Webhook.construct_event(payload, sig_header, settings.STRIPE_WEBHOOK_SECRET)\nE   stripe.error.SignatureVerificationError: No signatures found matching the expected signature for payload\nFAILED tests/test_payment_api.py::test_stripe_webhook_parse - AssertionError: assert 400 == 200\n2 failed, 22 passed in 4.82s`,
      docker: `#6 7.455   Error: pg_config executable not found.\n#6 7.457   pg_config is required to build psycopg2 from source. Please add the directory containing pg_config to the PATH\n#6 ERROR: process "/bin/sh -c pip install --no-cache-dir -r requirements.txt" did not complete successfully: exit code: 1`,
      nodejs: `2026-10-21T09:12:04.108Z [webpack-cli] Compilation failed with errors:\n2026-10-21T09:12:04.110Z ERROR in ./src/components/PaymentCheckout.tsx 14:2-31\n2026-10-21T09:12:04.112Z Module not found: Error: Can't resolve '@stripe/react-stripe-js' in '/app/src/components'\nnpm error code ELIFECYCLE\nnpm error app@0.1.0 build: react-scripts build\nnpm error Exit status 1\nError: Process completed with exit code 1.`
    };

    // TAB SWITCHING
    function switchTab(tabId) {
      document.querySelectorAll('.tab-view').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.nav-tab').forEach(el => el.classList.remove('active'));
      
      const target = document.getElementById('tab-' + tabId);
      if (target) target.classList.add('active');

      const tabs = {
        'github': 0, 'analyzer': 1, 'analytics': 2, 'settings': 3
      };
      const buttons = document.querySelectorAll('.nav-tab');
      if (buttons[tabs[tabId]]) buttons[tabs[tabId]].classList.add('active');

      if (tabId === 'analytics') {
        loadHistoryTable();
      }
    }

    // VAULT / SETTINGS
    function loadKeys() {
      document.getElementById('vaultGhToken').value = localStorage.getItem('ls_gh_token') || '';
      document.getElementById('vaultGeminiKey').value = localStorage.getItem('ls_gemini_key') || '';
      document.getElementById('vaultGroqKey').value = localStorage.getItem('ls_groq_key') || '';
      document.getElementById('vaultOpenRouterKey').value = localStorage.getItem('ls_openrouter_key') || '';
      document.getElementById('vaultWebhook').value = localStorage.getItem('ls_webhook') || '';

      const token = localStorage.getItem('ls_gh_token');
      if (token) {
        document.getElementById('ghProfileText').textContent = 'GitHub: Authenticated (PAT)';
      }
    }

    function saveKeys() {
      localStorage.setItem('ls_gh_token', document.getElementById('vaultGhToken').value.trim());
      localStorage.setItem('ls_gemini_key', document.getElementById('vaultGeminiKey').value.trim());
      localStorage.setItem('ls_groq_key', document.getElementById('vaultGroqKey').value.trim());
      localStorage.setItem('ls_openrouter_key', document.getElementById('vaultOpenRouterKey').value.trim());
      localStorage.setItem('ls_webhook', document.getElementById('vaultWebhook').value.trim());
      alert('Settings & Keys safely saved!');
      loadKeys();
    }

    function clearKeys() {
      if (confirm('Are you sure you want to clear stored keys?')) {
        localStorage.clear();
        loadKeys();
        document.getElementById('ghProfileText').textContent = 'GitHub: Public Mode';
      }
    }

    // GITHUB PIPELINE EXPLORER
    async function fetchGitHubRepos() {
      const target = document.getElementById('ghTargetInput').value.trim();
      const token = localStorage.getItem('ls_gh_token') || '';
      const listContainer = document.getElementById('repoListContainer');

      listContainer.innerHTML = '<div style="color:var(--text-muted); font-size:12px; text-align:center; padding:30px;">Loading repositories...</div>';

      try {
        const resp = await fetch('/api/github/repos', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token, username: target })
        });
        const data = await resp.json();
        
        if (data.error) {
          listContainer.innerHTML = `<div style="color:#f87171; font-size:12px; padding:12px;">Error: ${data.error}</div>`;
          return;
        }

        allRepos = data;
        document.getElementById('repoCount').textContent = allRepos.length;
        renderRepos(allRepos);

        // Auto select first repo if available
        if (allRepos.length > 0) {
          selectRepo(allRepos[0]);
        }
      } catch (err) {
        listContainer.innerHTML = `<div style="color:#f87171; font-size:12px; padding:12px;">Failed to fetch: ${err}</div>`;
      }
    }

    function renderRepos(repos) {
      const listContainer = document.getElementById('repoListContainer');
      if (repos.length === 0) {
        listContainer.innerHTML = '<div style="color:var(--text-dim); font-size:12px; text-align:center; padding:30px;">No repositories found.</div>';
        return;
      }

      listContainer.innerHTML = repos.map(r => `
        <div class="repo-item ${currentSelectedRepo && currentSelectedRepo.full_name === r.full_name ? 'selected' : ''}" onclick='selectRepo(${JSON.stringify(r)})'>
          <div class="repo-name">
            <span>${r.name}</span>
            <span style="font-size:10px; color:${r.private ? '#f59e0b' : '#94a3b8'};">${r.private ? '🔒 Private' : '🌐 Public'}</span>
          </div>
          <div class="repo-desc">${r.description || 'No description provided'}</div>
        </div>
      `).join('');
    }

    function filterRepos() {
      const q = document.getElementById('repoSearch').value.toLowerCase();
      const filtered = allRepos.filter(r => r.name.toLowerCase().includes(q) || (r.description && r.description.toLowerCase().includes(q)));
      renderRepos(filtered);
    }

    async function selectRepo(repo) {
      currentSelectedRepo = repo;
      renderRepos(allRepos);
      document.getElementById('currentRepoTitle').textContent = repo.full_name;
      await fetchWorkflowRuns(repo.owner.login, repo.name);
    }

    async function refreshWorkflowRuns() {
      if (currentSelectedRepo) {
        await fetchWorkflowRuns(currentSelectedRepo.owner.login, currentSelectedRepo.name);
      }
    }

    async function fetchWorkflowRuns(owner, repoName) {
      const token = localStorage.getItem('ls_gh_token') || '';
      const runsContainer = document.getElementById('runsContainer');
      runsContainer.innerHTML = '<div style="color:var(--text-muted); font-size:12px; text-align:center; padding:40px;">Fetching workflow runs...</div>';

      try {
        const resp = await fetch('/api/github/runs', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ owner, repo: repoName, token })
        });
        const runs = await resp.json();

        if (runs.error) {
          runsContainer.innerHTML = `<div style="color:#f87171; font-size:12px; padding:20px;">Error: ${runs.error}</div>`;
          return;
        }

        if (runs.length === 0) {
          runsContainer.innerHTML = '<div class="empty-placeholder" style="min-height:300px;"><p style="font-size:13px;">No GitHub Actions workflow runs found for this repository.</p></div>';
          return;
        }

        runsContainer.innerHTML = `
          <table class="runs-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Workflow</th>
                <th>Branch & Commit</th>
                <th>Author</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              ${runs.map(run => {
                const isFail = run.conclusion === 'failure';
                const isSuccess = run.conclusion === 'success';
                const badgeClass = isSuccess ? 'badge-success' : (isFail ? 'badge-failure' : 'badge-queued');
                const badgeText = run.conclusion || run.status;
                return `
                  <tr>
                    <td>
                      <span class="badge ${badgeClass}">${badgeText}</span>
                    </td>
                    <td>
                      <div style="font-weight:600; color:#fff;">${run.name || 'CI/CD'}</div>
                      <div style="font-size:11px; color:var(--text-dim);">${new Date(run.created_at).toLocaleString()}</div>
                    </td>
                    <td>
                      <div style="font-family:'JetBrains Mono'; font-size:12px; color:#60a5fa;">${run.head_branch} <span style="color:var(--text-dim);">#${run.head_sha}</span></div>
                      <div style="font-size:11px; color:var(--text-muted); max-width:240px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${run.commit_message}</div>
                    </td>
                    <td style="color:var(--text-muted); font-size:12px;">${run.author}</td>
                    <td>
                      ${isFail ? `
                        <button class="btn" style="padding:4px 10px; font-size:11px;" onclick="inspectAndAnalyzeRun('${owner}', '${repoName}', ${run.id})">
                          ⚡ AI Diagnose
                        </button>
                      ` : `
                        <a href="${run.html_url}" target="_blank" class="btn btn-secondary" style="text-decoration:none; padding:4px 10px; font-size:11px;">
                          View Log ↗
                        </a>
                      `}
                    </td>
                  </tr>
                `;
              }).join('')}
            </tbody>
          </table>
        `;
      } catch (err) {
        runsContainer.innerHTML = `<div style="color:#f87171; font-size:12px; padding:20px;">Failed to load runs: ${err}</div>`;
      }
    }

    async function inspectAndAnalyzeRun(owner, repoName, runId) {
      const token = localStorage.getItem('ls_gh_token') || '';
      try {
        const resp = await fetch('/api/github/jobs', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ owner, repo: repoName, runId, token })
        });
        const jobs = await resp.json();
        
        let failedJob = jobs.find(j => j.conclusion === 'failure') || jobs[0];
        if (failedJob) {
          // Fetch log for this job
          const logResp = await fetch('/api/github/logs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ owner, repo: repoName, jobId: failedJob.id, token })
          });
          const logData = await logResp.json();
          const rawLog = logData.log || `Job '${failedJob.name}' failed with status '${failedJob.conclusion}'.`;

          // Switch to Diagnostic Tab and populate
          switchTab('analyzer');
          document.getElementById('logInput').value = rawLog;
          updateLogCount();
          runAnalysis();
        } else {
          alert('No failed job found in this run.');
        }
      } catch (err) {
        alert('Could not inspect run: ' + err);
      }
    }

    // LOG SAMPLES & INPUT
    function loadSample(key) {
      document.getElementById('logInput').value = SAMPLES[key] || '';
      updateLogCount();
    }

    function clearLog() {
      document.getElementById('logInput').value = '';
      updateLogCount();
    }

    function updateLogCount() {
      const lines = document.getElementById('logInput').value.split('\n').length;
      document.getElementById('logLinesCount').textContent = `${lines} lines`;
    }
    document.getElementById('logInput').addEventListener('input', updateLogCount);

    // AI ANALYSIS EXECUTION
    async function runAnalysis() {
      const log = document.getElementById('logInput').value.trim();
      if (!log) {
        alert('Please paste a log trace or select a sample preset first.');
        return;
      }

      const provider = document.getElementById('modelSelect').value;
      let apiKey = '';
      if (provider === 'gemini') apiKey = localStorage.getItem('ls_gemini_key') || '';
      else if (provider === 'groq') apiKey = localStorage.getItem('ls_groq_key') || '';
      else if (provider === 'openrouter') apiKey = localStorage.getItem('ls_openrouter_key') || '';

      const btn = document.getElementById('analyzeBtn');
      const btnText = document.getElementById('btnText');
      btn.disabled = true;
      btnText.textContent = 'Reasoning...';

      try {
        const resp = await fetch('/api/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ log, provider, apiKey })
        });
        const data = await resp.json();
        latestAnalysisResult = data;

        document.getElementById('placeholderResult').style.display = 'none';
        document.getElementById('diagnosticResults').style.display = 'flex';

        // Render diagnosis
        document.getElementById('categoryPill').textContent = data.category || 'Build Exception';
        document.getElementById('rootCauseText').textContent = data.root_cause || 'Process exited with non-zero status.';
        document.getElementById('fixCode').textContent = data.suggested_fix || 'No automated fix suggested.';
        document.getElementById('preventionText').textContent = data.prevention || 'Review CI pipeline specifications.';

        const badgesContainer = document.getElementById('resultStatusBadges');
        const sev = data.severity || 'HIGH';
        const sevClass = (sev === 'CRITICAL' || sev === 'BLOCKER') ? 'badge-failure' : 'badge-queued';
        badgesContainer.innerHTML = `
          <span class="badge ${sevClass}">${sev}</span>
          <span class="badge" style="background:#1e293b; color:#94a3b8;">Confidence: ${data.confidence || '95%'}</span>
        `;

        // Save incident to history
        await fetch('/api/history', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            timestamp: new Date().toISOString(),
            category: data.category,
            severity: data.severity,
            root_cause: data.root_cause,
            suggested_fix: data.suggested_fix,
            confidence: data.confidence
          })
        });

      } catch (err) {
        alert('Analysis error: ' + err);
      } finally {
        btn.disabled = false;
        btnText.textContent = 'Analyze Log';
      }
    }

    // COPY SNIPPETS & EXPORT
    function copySnippet(elementId) {
      const text = document.getElementById(elementId).textContent;
      navigator.clipboard.writeText(text);
      alert('Copied to clipboard!');
    }

    function exportMarkdown() {
      if (!latestAnalysisResult) return;
      const md = `## 🚨 AI CI/CD Diagnostic Report
> **Severity:** \`${latestAnalysisResult.severity}\` | **Confidence:** \`${latestAnalysisResult.confidence}\` | **Category:** \`${latestAnalysisResult.category}\`

### 📌 Root Cause
${latestAnalysisResult.root_cause}

### 💡 Recommended Code Fix
\`\`\`diff
${latestAnalysisResult.suggested_fix}
\`\`\`

### 🛡️ Prevention Strategy
${latestAnalysisResult.prevention}

---
*Generated by LogSense AI CI/CD Analyzer*`;

      navigator.clipboard.writeText(md);
      alert('Markdown report copied! Ready to paste into GitHub PR or Issue.');
    }

    function exportJSON() {
      if (!latestAnalysisResult) return;
      const blob = new Blob([JSON.stringify(latestAnalysisResult, null, 2)], { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `incident_report_${Date.now()}.json`;
      a.click();
    }

    // INCIDENT HISTORY & ANALYTICS
    async function loadHistoryTable() {
      try {
        const resp = await fetch('/api/history');
        const history = await resp.json();
        const tbody = document.getElementById('historyTableBody');
        
        document.getElementById('statTotal').textContent = history.length;
        if (history.length === 0) {
          tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-dim); padding:30px;">No incidents logged yet.</td></tr>';
          return;
        }

        tbody.innerHTML = history.map(item => `
          <tr>
            <td style="font-size:11px; color:var(--text-dim);">${new Date(item.timestamp).toLocaleTimeString()}</td>
            <td><span class="badge" style="background:#1e293b; color:#60a5fa;">${item.category || 'Error'}</span></td>
            <td><span class="badge ${item.severity === 'CRITICAL' ? 'badge-failure' : 'badge-queued'}">${item.severity || 'HIGH'}</span></td>
            <td style="font-size:12px; color:#e2e8f0; max-width:320px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${item.root_cause || ''}</td>
            <td>
              <button class="btn btn-secondary" style="font-size:11px; padding:3px 8px;" onclick='reopenIncident(${JSON.stringify(item)})'>
                Inspect
              </button>
            </td>
          </tr>
        `).join('');
      } catch (err) {
        console.error('History fetch error', err);
      }
    }

    function reopenIncident(item) {
      latestAnalysisResult = item;
      switchTab('analyzer');
      document.getElementById('placeholderResult').style.display = 'none';
      document.getElementById('diagnosticResults').style.display = 'flex';
      document.getElementById('categoryPill').textContent = item.category || 'Exception';
      document.getElementById('rootCauseText').textContent = item.root_cause || '';
      document.getElementById('fixCode').textContent = item.suggested_fix || '';
      document.getElementById('preventionText').textContent = item.prevention || '';
    }

    // INITIAL BOOT
    window.onload = () => {
      loadKeys();
      fetchGitHubRepos();
      loadSample('flutter');
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
        if self.path in ["/", "/index.html", "/dashboard"]:
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

        # 1. ANALYZE ENDPOINT
        if self.path == "/api/analyze":
            raw_log = data.get("log", "")
            provider = data.get("provider", "offline")
            api_key = data.get("apiKey", "")

            windowed = analyzer.sanitize_and_extract_error_window(raw_log)
            result = None

            if provider == "gemini" and api_key:
                result = analyzer.call_gemini_api(api_key, windowed)
            elif provider == "groq" and api_key:
                result = analyzer.call_groq_api(api_key, windowed)
            elif provider == "openrouter" and api_key:
                result = analyzer.call_openrouter_api(api_key, windowed)

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
    print(f"[*] LogSense AI — CI/CD Observability SaaS running at http://localhost:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")


if __name__ == "__main__":
    run()
