#!/usr/bin/env python3
"""
CI Log Analyzer - Production AIOps Observability SaaS Platform (HeroUI Edition)
Author: Yash Dodani (github.com/Yash-Dodani)
Design: HeroUI Pro (https://heroui.pro/) Obsidian Dark Theme
Features:
 - Pure Pitch-Black Obsidian Aesthetic (#000000, #09090b, #121216) with HeroUI Cards & Glassmorphic Blur
 - Full GitHub PAT Gatekeeper & Real-Time Public/Private Repository Workflow Inspector
 - Zero 'undefined' guarantee across all incidents and runs
 - Multi-LLM Diagnostic Engine (OpenRouter Llama 3.3 Free, Groq, Gemini, Offline Heuristics)
 - Actionable Fix Prompts (for Cursor / Copilot) and Step-by-Step CLI Remediation
 - Ottie Mascot Illustrations & Custom Animated SVG Brand Logo / Favicon
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

# Simple .env loader with zero external dependencies
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
                data = json.load(f)
                cleaned = []
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    t = item.get("title")
                    if not t or str(t).strip() in ("undefined", "null", ""):
                        t = item.get("category") or "CI/CD Pipeline Failure"
                    item["title"] = str(t).strip()
                    item["env_info"] = item.get("env_info") or "Python • GitHub Actions"
                    item["severity"] = item.get("severity") or "High"
                    item["time_ago"] = item.get("time_ago") or "Recent"
                    item["confidence"] = item.get("confidence") or "0.94"
                    cleaned.append(item)
                return cleaned
        except Exception:
            return []
    return []


def save_history(entry: Dict[str, Any]):
    history = load_history()
    t = entry.get("title")
    if not t or str(t).strip() in ("undefined", "null", ""):
        t = entry.get("category") or "CI/CD Pipeline Failure"
    entry["title"] = str(t).strip()
    entry["env_info"] = entry.get("env_info") or "Manual Trace • GitHub Actions"
    entry["time_ago"] = "Just now"

    history = [h for h in history if h.get("id") != entry.get("id")]
    history.insert(0, entry)
    history = history[:50]
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2)
    except Exception as e:
        print(f"[!] Could not save incident history: {e}")


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
        # Serve static assets (such as ottie images and SVG logo/favicon)
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

        # Serve index.html dynamically from disk
        if self.path in ["/", "/index.html", "/dashboard", "/analyze", "/history", "/integrations", "/settings"]:
            index_path = os.path.join(BASE_DIR, "index.html")
            if os.path.exists(index_path):
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                with open(index_path, "rb") as f:
                    self.wfile.write(f.read())
                return
            else:
                self.send_error(404, "index.html Not Found")
                return

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

            if provider == "openrouter" and api_key:
                result = analyzer.call_openrouter_api(api_key, windowed)
            elif provider == "groq" and api_key:
                result = analyzer.call_groq_api(api_key, windowed)
            elif provider == "gemini" and api_key:
                result = analyzer.call_gemini_api(api_key, windowed)

            if not result:
                result = analyzer.run_offline_heuristics(windowed)

            self.send_json_response(200, result)

        # 2. GITHUB USER AUTH
        elif self.path == "/api/github/user":
            token = data.get("token") or None
            if not token:
                self.send_json_response(400, {"error": "Token is required"})
            else:
                try:
                    user_info = analyzer.fetch_github_user(token)
                    self.send_json_response(200, user_info)
                except Exception as e:
                    self.send_json_response(400, {"error": str(e)})

        # 3. GITHUB REPOSITORIES
        elif self.path == "/api/github/repos":
            token = data.get("token") or None
            username = data.get("username") or None
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
