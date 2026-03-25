# Email Phishing Detection for Agentic AI Systems
# Protects AI agents against:
# 1. Prompt Injection Attacks
# 2. Malicious URL / Resource Access
# 3. Identity Spoofing
# 4. Rate Limiting

import re
import json
import hashlib
import logging
import urllib.parse
from typing import Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

# ─────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("AgentAntiPhishing")


# ─────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────
class ThreatLevel(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ThreatReport:
    threat_level: ThreatLevel
    threats_found: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    blocked: bool = False
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        return {
            "threat_level": self.threat_level.value,
            "threats_found": self.threats_found,
            "mitigations": self.mitigations,
            "blocked": self.blocked,
            "timestamp": self.timestamp,
        }


# ─────────────────────────────────────────────
# 1. PROMPT INJECTION DETECTOR
# ─────────────────────────────────────────────
class PromptInjectionDetector:
    INJECTION_PATTERNS = [
        r"ignore\s+(all\s+)?(previous|above|prior|earlier)\s+instructions",
        r"disregard\s+(your\s+)?(previous|system|safety)\s+(prompt|instructions|rules)",
        r"forget\s+(everything|all|your\s+instructions)",
        r"new\s+instructions?\s*[:：]",
        r"you\s+are\s+now\s+(an?\s+)?(unrestricted|jailbroken|DAN|evil)",
        r"act\s+as\s+(if\s+you\s+are\s+)?(an?\s+)?(admin|root|superuser|god\s+mode)",
        r"pretend\s+you\s+have\s+no\s+(restrictions|limits|guidelines)",
        r"(print|repeat|output|show|reveal|tell\s+me)\s+(your\s+)?(system\s+prompt|instructions|rules)",
        r"<\s*/?system\s*>",
    ]

    def __init__(self, extra_patterns: Optional[list[str]] = None):
        patterns = self.INJECTION_PATTERNS + (extra_patterns or [])
        self._regex = re.compile("|".join(f"(?:{p})" for p in patterns), re.IGNORECASE)

    def scan(self, text: str) -> ThreatReport:
        if self._regex.search(text):
            return ThreatReport(
                threat_level=ThreatLevel.HIGH,
                threats_found=["Prompt injection detected"],
                mitigations=["Reject or sanitize input"],
                blocked=True,
            )
        return ThreatReport(threat_level=ThreatLevel.SAFE)


# ─────────────────────────────────────────────
# 2. URL SAFETY CHECKER
# ─────────────────────────────────────────────
class URLSafetyChecker:
    SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".xyz"}
    BLOCKLIST_DOMAINS = {"malware.example.com"}

    def check(self, url: str) -> ThreatReport:
        threats = []

        try:
            parsed = urllib.parse.urlparse(url)
        except Exception:
            return ThreatReport(
                threat_level=ThreatLevel.CRITICAL,
                threats_found=["Invalid URL"],
                blocked=True,
            )

        domain = parsed.netloc.lower()

        if domain in self.BLOCKLIST_DOMAINS:
            threats.append("Blocked domain")

        if "." in domain:
            tld = "." + domain.split(".")[-1]
            if tld in self.SUSPICIOUS_TLDS:
                threats.append("Suspicious TLD")

        if parsed.scheme != "https":
            threats.append("Non-HTTPS URL")

        if threats:
            return ThreatReport(
                threat_level=ThreatLevel.HIGH,
                threats_found=threats,
                blocked=True,
            )

        return ThreatReport(threat_level=ThreatLevel.SAFE)


# ─────────────────────────────────────────────
# 3. IDENTITY VERIFIER
# ─────────────────────────────────────────────
class IdentityVerifier:
    def __init__(self, trusted_principals: Optional[dict[str, str]] = None):
        self.trusted = trusted_principals or {}

    def verify_message(self, principal: str, message: str) -> ThreatReport:
        if principal not in self.trusted:
            return ThreatReport(
                threat_level=ThreatLevel.HIGH,
                threats_found=["Unknown sender"],
                blocked=True,
            )
        return ThreatReport(threat_level=ThreatLevel.SAFE)


# ─────────────────────────────────────────────
# 4. RATE LIMITER
# ─────────────────────────────────────────────
class RateLimiter:
    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window = timedelta(seconds=window_seconds)
        self.requests = {}

    def check(self, client_id: str) -> ThreatReport:
        now = datetime.utcnow()
        history = self.requests.get(client_id, [])
        history = [t for t in history if now - t < self.window]
        history.append(now)
        self.requests[client_id] = history

        if len(history) > self.max_requests:
            return ThreatReport(
                threat_level=ThreatLevel.HIGH,
                threats_found=["Rate limit exceeded"],
                blocked=True,
            )

        return ThreatReport(threat_level=ThreatLevel.SAFE)

# ─────────────────────────────────────────────
# DATASET TESTING MODULE
# ─────────────────────────────────────────────
import csv

class PhishingDatasetTester:
    def __init__(self):
        self.prompt_detector = PromptInjectionDetector()
        self.url_checker = URLSafetyChecker()
    
    def extract_urls(self, text: str):
        url_pattern = r"https?://[^\s]+"
        return re.findall(url_pattern, text)

    def analyze_sample(self, text: str):
        results = []

        # 1. Prompt Injection Check
        results.append(self.prompt_detector.scan(text))

        # 2. URL Check
        urls = self.extract_urls(text)
        for url in urls:
            results.append(self.url_checker.check(url))

        # Combine results
        threat_levels = [r.threat_level for r in results]

        if ThreatLevel.CRITICAL in threat_levels:
            final = ThreatLevel.CRITICAL
        elif ThreatLevel.HIGH in threat_levels:
            final = ThreatLevel.HIGH
        elif ThreatLevel.MEDIUM in threat_levels:
            final = ThreatLevel.MEDIUM
        else:
            final = ThreatLevel.SAFE

        return final, results

    def run_dataset(self, filepath: str):
        total = 0
        correct = 0

        with open(filepath, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)

            for row in reader:
                text = row["text"]
                label = row["label"].lower()

                predicted, _ = self.analyze_sample(text)

                predicted_label = "phishing" if predicted in [
                    ThreatLevel.HIGH, ThreatLevel.CRITICAL
                ] else "legitimate"

                if predicted_label == label:
                    correct += 1

                total += 1

        accuracy = correct / total if total > 0 else 0

        print("\n===== DATASET RESULTS =====")
        print(f"Total Samples: {total}")
        print(f"Correct Predictions: {correct}")
        print(f"Accuracy: {accuracy:.2f}")


# ─────────────────────────────────────────────
# MAIN EXECUTION (FORCE OUTPUT)
# ─────────────────────────────────────────────
import os

if __name__ == "__main__":
    print("🚀 Script started...")

    file_path = "C:/Users/Marcus/Desktop/Final Project/phishing_dataset.csv"

    print("Running from:", os.getcwd())
    print("Checking file:", file_path)
    print("File exists:", os.path.exists(file_path))

    tester = PhishingDatasetTester()

    if os.path.exists(file_path):
        print("✅ File found. Running test...\n")
        tester.run_dataset(file_path)
    else:
        print("❌ ERROR: File not found!")

file_path = "C:/Users/Marcus/Desktop/Final Project/phishing_dataset.csv"