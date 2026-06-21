# ============================================================
# Project 3: Phishing Awareness Analysis
# Phishing Triage Toolkit | Saurabh Cybersecurity 2026
# ============================================================

# ─────────────────────────────────────────────
# ALL 11 RED FLAGS from PDF (Pages 11-13)
# ─────────────────────────────────────────────
RED_FLAG_KEYWORDS = {
    "RF1 - Sender/Domain Mismatch": [
        "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
        "logins-updates", "login-update", "secure-login", "account-alert"
    ],
    "RF2 - Fake Forwarded Chains": [
        "fw:", "fwd:", "forwarded message"
    ],
    "RF4 - Dangerous Attachments": [
        ".iso", ".js", ".scr", ".exe", ".bat", ".vbs"
    ],
    "RF5 - Urgent Bypass Requests": [
        "do not discuss", "strictly confidential", "bypass procedure",
        "bypass standard", "do not tell", "keep this secret"
    ],
    "RF6 - Request for Sensitive Info": [
        "mfa code", "otp", "password", "update billing",
        "confirm your details", "verify your account",
        "enter your credentials", "payment detail"
    ],
    "RF7 - Activity / Sign-in Alerts": [
        "unusual sign-in", "account locked", "suspicious activity",
        "security alert", "login attempt", "verify now"
    ],
    "RF8 - MFA Fatigue": [
        "approve sign-in", "mfa request", "authentication request",
        "confirm login", "approve this request"
    ],
    "RF9 - Security Callback Scam (TOAD)": [
        "call 1-800", "call us immediately", "call this number",
        "subscription charge", "call to cancel"
    ],
    "RF10 - QR Code Prompts": [
        "scan the qr", "scan to unlock", "scan to verify",
        "qr code", "scan this code"
    ],
    "RF11 - Deepfake / Executive Fraud": [
        "wire transfer", "transfer funds", "lost my wallet",
        "urgent wire", "immediate transfer", "ceo", "director"
    ],
    "RF3 - Urgency / Fear Trigger (Psychology)": [
        "urgent", "immediately", "account will be closed",
        "expires in 24", "act now", "last warning",
        "immediate action required", "your account has been"
    ],
}

# Suspicious domain patterns (Page 9 of PDF - Typosquatting etc.)
SUSPICIOUS_DOMAIN_PATTERNS = [
    "amaz0n", "paypa1", "g00gle", "micosoft", "arnazon",
    "secure-login", "login-update", "account-verify",
    "support-desk", "helpdesk-", "-secure", "logins-"
]


# ─────────────────────────────────────────────
# CORE ANALYSIS FUNCTIONS
# ─────────────────────────────────────────────

def analyze_email(sender, subject, body):
    """
    Main triage function.
    Checks all 11 Red Flags from PDF and scores the email.
    Returns: verdict (Safe / Suspicious / Malicious), red flags found, reason
    """
    found_flags = []
    full_text = (sender + " " + subject + " " + body).lower()

    # Check each red flag category
    for flag_name, keywords in RED_FLAG_KEYWORDS.items():
        for keyword in keywords:
            if keyword.lower() in full_text:
                found_flags.append(f"🚩 {flag_name}  →  Keyword: '{keyword}'")
                break  # one match per category is enough

    # Check suspicious domain patterns in sender
    for pattern in SUSPICIOUS_DOMAIN_PATTERNS:
        if pattern.lower() in sender.lower():
            found_flags.append(f"🚩 RF1 - Suspicious Domain Pattern  →  '{pattern}' found in sender")
            break

    # ─── TRIAGE DECISION TREE (PDF Page 17) ───
    score = len(found_flags)

    if score == 0:
        verdict = "✅ SAFE"
        action  = "ACTION → CLOSE (No threat detected)"
        reason  = "No phishing indicators found."
    elif score <= 2:
        verdict = "⚠️  SUSPICIOUS"
        action  = "ACTION → WARN USER (Proceed with caution)"
        reason  = "Some phishing indicators detected. Verify sender via alternate channel."
    else:
        verdict = "🔴 MALICIOUS"
        action  = "ACTION → BLOCK DOMAIN & ESCALATE to security team"
        reason  = "Multiple phishing indicators detected. Do NOT click any links or attachments."

    return verdict, action, reason, found_flags


def display_report(sender, subject, body, verdict, action, reason, flags):
    """Displays the full triage report."""
    print("\n" + "=" * 60)
    print("  Saurabh — Phishing Triage Report")
    print("=" * 60)
    print(f"  FROM    : {sender}")
    print(f"  SUBJECT : {subject}")
    print("-" * 60)

    if flags:
        print(f"\n  RED FLAGS DETECTED ({len(flags)}):")
        for f in flags:
            print(f"    {f}")
    else:
        print("\n  No red flags found.")

    print(f"\n  VERDICT : {verdict}")
    print(f"  REASON  : {reason}")
    print(f"  {action}")
    print("=" * 60)


# ─────────────────────────────────────────────
# SAMPLE PHISHING EMAILS (from PDF scenarios)
# ─────────────────────────────────────────────

SAMPLE_EMAILS = [
    {
        "label": "Sample 1 — BEC: CEO Wire Transfer (PDF Page 15)",
        "sender": "CEO Name <hacker@gmail.com>",
        "subject": "Urgent Wire Transfer Request",
        "body": (
            "I lost my wallet at the airport. "
            "Need you to wire transfer funds for my flight immediately. "
            "Do not discuss with anyone. Bypass standard procedure. "
            "This is strictly confidential. - CEO"
        )
    },
    {
        "label": "Sample 2 — Microsoft Phishing (PDF Page 11)",
        "sender": "Microsoft Support <support@logins-updates.com>",
        "subject": "FW: Urgent: Your Account Security Alert",
        "body": (
            "Your account will be closed. Immediate action required. "
            "Please verify your account and enter your credentials. "
            "Download attachment: Security_Update_2024.iso"
        )
    },
    {
        "label": "Sample 3 — Legitimate Email (PDF Page 13)",
        "sender": "Project Manager <sarah.lee@company.com>",
        "subject": "Q3 Project Status Update - Non-Urgent",
        "body": (
            "Hi Team, Please review the attached project status for Q3 "
            "at your earliest convenience. No immediate action is required. "
            "Thanks, Sarah."
        )
    },
    {
        "label": "Sample 4 — TOAD Callback Scam (PDF Page 16)",
        "sender": "Microsoft Billing <noreply@microsofft-renewal.com>",
        "subject": "PAYMENT OVERDUE: Microsoft Subscription Renewal",
        "body": (
            "Your subscription is overdue. "
            "Call 1-800-XXX-XXXX to cancel IMMEDIATELY. "
            "Subscription charge of $190.60 pending."
        )
    },
]


# ─────────────────────────────────────────────
# MAIN PROGRAM
# ─────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  Saurabh — Phishing Awareness Triage Toolkit")
    print("  Project 3 | Batch 2026")
    print("=" * 60)
    print("\nChoose mode:")
    print("  1. Analyze sample phishing emails (from PDF)")
    print("  2. Enter your own email to analyze")
    choice = input("\nEnter choice (1 or 2): ").strip()

    if choice == "1":
        print("\nRunning all sample emails...\n")
        for email in SAMPLE_EMAILS:
            print(f"\n>>> {email['label']}")
            verdict, action, reason, flags = analyze_email(
                email["sender"], email["subject"], email["body"]
            )
            display_report(
                email["sender"], email["subject"], email["body"],
                verdict, action, reason, flags
            )

    elif choice == "2":
        print("\nEnter email details:")
        sender  = input("  Sender (From): ").strip()
        subject = input("  Subject      : ").strip()
        print("  Body (press Enter twice when done):")
        lines = []
        while True:
            line = input()
            if line == "":
                break
            lines.append(line)
        body = " ".join(lines)

        verdict, action, reason, flags = analyze_email(sender, subject, body)
        display_report(sender, subject, body, verdict, action, reason, flags)

    else:
        print("Invalid choice. Please run again.")


if __name__ == "__main__":
    main()