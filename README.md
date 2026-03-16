# Email-Phishing-Detection-with-AI
 Email Phishing Detection with AI
The sheild covers 4 key attack surfaces specific to Agentic AI

1. Prompt Injection Detector- examines user/external content for attempts to override system instructions, jailbreak the agent, or extract its system prompt using regex-based pattern matching.

2. URL Safety Checker- validates URLs before the agent fetches them, using an allowlist/blocklist, suspicious TLD detection (.tk, .ml, etc.), phishing heuristics (typosquatted domains, credential-harvesting paths, IP-only hosts), and enforces HTTPS.

3. Identity Verifier- prevents impersonation of trusted orchestrators or other agents using HMAC token verification, and detects social-engineering language like urgency cues ("URGENT: act now").

4. Rate Limiter(Brute-force / Spam Guard)- blocks flooding attacks that try to overwhelm safety checks by probing the agent at high speed.
