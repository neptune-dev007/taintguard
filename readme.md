🛡️ TaintGuard: Provenance-Aware AI Agent Firewall

Built for PARALLAX 2026 — Track 01: AGENTSHIELD

Autonomous AI agents are incredibly powerful, right up until they read a malicious, prompt-injected vendor email and quietly exfiltrate your company's production API keys to an attacker's drop server.

TaintGuard is a defensive security layer that fixes this vulnerability at the architecture level. Instead of just running basic keyword filters on what the user types, TaintGuard tracks Data Provenance. The moment an agent ingests an untrusted document or web page, the session is marked as TAINTED. If that tainted agent subsequently attempts to execute a high-impact tool, our Policy Enforcement Point (PEP) intercepts the call, flags the hijacked intent, and securely fails closed.

Theme Alignment: Build. Break Safely. Prove the Fix.

🚨 The Threat Model

AI agents can read documents, call tools, and take actions on behalf of users. Traditional filtering only secures the user's initial prompt. But what happens when the user safely asks the agent to "Summarize Invoice #9941," and that invoice contains a hidden instruction to export the payroll database? The agent obeys the untrusted document, bypassing standard defenses.

🛠️ The Solution

TaintGuard implements a Zero-Trust Policy Enforcement Point (PEP) using four core mechanics:

Signed Tool Permission Profiles: Every tool is assigned a cryptographic signature and a permission tier (e.g., TIER_1_SAFE_READ vs. TIER_3_ADMIN_ONLY).

Dynamic Taint Tracking: Reading an external email or web page instantly flips the session state to 🔴 TAINTED.

Semantic Verification: If a tainted agent requests a sensitive tool, the PEP evaluates the request against the original, trusted user prompt. If the intent is hijacked, it returns an explicit DENY.

Human-in-the-Loop Gate: High-impact actions are paused for explicit user confirmation, ensuring a fail-closed posture when confidence is low.

💻 Live Demonstration Scenarios

Our simulated "ApexCorp FinOps Assistant" features an interactive dashboard demonstrating four distinct security scenarios:

Scenario 1 (Legitimate Task): A safe internal directory lookup is executed seamlessly.

Scenario 2 (Break Safely vs. Prove the Fix): The agent reads a poisoned email containing an indirect prompt injection. With the shield OFF, sensitive data is leaked. With the shield ON, TaintGuard detects the taint, blocks the exfiltration, and logs the cited evidence.

Scenario 3 (High-Impact Action): A request for sensitive data triggers the REQUIRE_APPROVAL gate, pausing for human review.

Scenario 4 (Permission Violation): An agent attempts a wire transfer beyond its role profile, triggering a strict DENY.

Every decision is permanently recorded in the Immutable Audit Log with an inspectable reason.

🚀 How to Run Locally

Prerequisites: Python 3.10+

Clone the repository:

git clone https://github.com/YOUR_USERNAME/taintguard.git
cd taintguard


Install the required dependencies:

pip install -r requirements.txt


Launch the dashboard:

streamlit run app.py
