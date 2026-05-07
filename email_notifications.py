# ── ADD THIS to your app.py ───────────────────────────────────────────────────
# Add these imports at the top of app.py:
# import smtplib
# from email.mime.text import MIMEText
# from email.mime.multipart import MIMEMultipart

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ── EMAIL CONFIG ──────────────────────────────────────────────────────────────
SMTP_EMAIL    = "ramcharanreddy0422@gmail.com"
SMTP_PASSWORD = "yupn xbxr gzug xdws"
SMTP_HOST     = "smtp.gmail.com"
SMTP_PORT     = 587

def send_email(to_email, subject, html_body):
    """Send an HTML email via Gmail SMTP."""
    if not to_email or "@" not in to_email:
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"PhishDect <{SMTP_EMAIL}>"
        msg["To"]      = to_email
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.sendmail(SMTP_EMAIL, to_email, msg.as_string())
        print(f"✅ Email sent to {to_email}")
        return True
    except Exception as e:
        print(f"❌ Email error: {e}")
        return False


def email_received(to_email, url):
    """Sent immediately when report is submitted."""
    subject = "✅ We received your PhishDect report"
    html = f"""
    <div style="font-family:sans-serif;max-width:560px;margin:0 auto;background:#0a0f0a;color:#e8f5e8;border-radius:12px;overflow:hidden;">
      <div style="background:#111811;padding:24px 32px;border-bottom:2px solid #22c55e;">
        <h1 style="margin:0;font-size:22px;color:#22c55e;letter-spacing:-0.5px;">PhishDect</h1>
        <p style="margin:4px 0 0;font-size:12px;color:#6b8f6b;">Community-Based Phishing Detection</p>
      </div>
      <div style="padding:32px;">
        <h2 style="font-size:18px;margin:0 0 12px;">Report Received ✅</h2>
        <p style="color:#9ca3af;font-size:14px;line-height:1.7;margin:0 0 20px;">
          Thanks for helping keep the internet safer! We've received your report and our team will review it shortly.
        </p>
        <div style="background:#111811;border:1px solid #1e2e1e;border-radius:8px;padding:16px;margin-bottom:20px;">
          <p style="font-size:11px;color:#6b8f6b;margin:0 0 6px;text-transform:uppercase;letter-spacing:0.1em;">Reported URL</p>
          <p style="font-family:monospace;font-size:13px;color:#22c55e;margin:0;word-break:break-all;">{url}</p>
        </div>
        <div style="background:#1a2e1a;border:1px solid #166534;border-radius:8px;padding:14px;">
          <p style="font-size:13px;color:#86efac;margin:0;line-height:1.6;">
            🔍 Our team reviews every report manually.<br>
            📧 You'll get another email when we make a decision.<br>
            🛡️ Confirmed threats get added to our blocklist.
          </p>
        </div>
      </div>
      <div style="padding:16px 32px;border-top:1px solid #1e2e1e;text-align:center;">
        <p style="font-size:11px;color:#4b5563;margin:0;">PhishDect · <a href="https://phishdect.ddns.net" style="color:#22c55e;">phishdect.ddns.net</a></p>
      </div>
    </div>
    """
    return send_email(to_email, subject, html)


def email_approved(to_email, url):
    """Sent when admin approves a report."""
    subject = "🚨 Report Approved — Threat Confirmed"
    html = f"""
    <div style="font-family:sans-serif;max-width:560px;margin:0 auto;background:#0a0f0a;color:#e8f5e8;border-radius:12px;overflow:hidden;">
      <div style="background:#111811;padding:24px 32px;border-bottom:2px solid #ef4444;">
        <h1 style="margin:0;font-size:22px;color:#22c55e;letter-spacing:-0.5px;">PhishDect</h1>
        <p style="margin:4px 0 0;font-size:12px;color:#6b8f6b;">Community-Based Phishing Detection</p>
      </div>
      <div style="padding:32px;">
        <h2 style="font-size:18px;margin:0 0 12px;color:#ef4444;">Threat Confirmed 🚨</h2>
        <p style="color:#9ca3af;font-size:14px;line-height:1.7;margin:0 0 20px;">
          Great catch! Our team has reviewed and <strong style="color:#ef4444;">confirmed</strong> the URL you reported as a phishing threat.
          It has been added to our blocklist and the extension will now warn all users.
        </p>
        <div style="background:#111811;border:1px solid #ef444440;border-radius:8px;padding:16px;margin-bottom:20px;">
          <p style="font-size:11px;color:#6b8f6b;margin:0 0 6px;text-transform:uppercase;letter-spacing:0.1em;">Confirmed Phishing URL</p>
          <p style="font-family:monospace;font-size:13px;color:#ef4444;margin:0;word-break:break-all;">{url}</p>
        </div>
        <div style="background:#1a1a0a;border:1px solid #92400e;border-radius:8px;padding:14px;">
          <p style="font-size:13px;color:#fbbf24;margin:0;line-height:1.6;">
            🛡️ This URL is now on the PhishDect blocklist.<br>
            👥 All extension users will be warned automatically.<br>
            🙏 Thank you for keeping the community safe!
          </p>
        </div>
      </div>
      <div style="padding:16px 32px;border-top:1px solid #1e2e1e;text-align:center;">
        <p style="font-size:11px;color:#4b5563;margin:0;">PhishDect · <a href="https://phishdect.ddns.net" style="color:#22c55e;">phishdect.ddns.net</a></p>
      </div>
    </div>
    """
    return send_email(to_email, subject, html)


def email_rejected(to_email, url):
    """Sent when admin rejects a report."""
    subject = "ℹ️ Report Reviewed — Not Confirmed"
    html = f"""
    <div style="font-family:sans-serif;max-width:560px;margin:0 auto;background:#0a0f0a;color:#e8f5e8;border-radius:12px;overflow:hidden;">
      <div style="background:#111811;padding:24px 32px;border-bottom:2px solid #3b82f6;">
        <h1 style="margin:0;font-size:22px;color:#22c55e;letter-spacing:-0.5px;">PhishDect</h1>
        <p style="margin:4px 0 0;font-size:12px;color:#6b8f6b;">Community-Based Phishing Detection</p>
      </div>
      <div style="padding:32px;">
        <h2 style="font-size:18px;margin:0 0 12px;color:#3b82f6;">Report Reviewed ℹ️</h2>
        <p style="color:#9ca3af;font-size:14px;line-height:1.7;margin:0 0 20px;">
          Thank you for your report! After careful review, our team was unable to confirm this URL as a phishing threat at this time.
          It will not be added to the blocklist.
        </p>
        <div style="background:#111811;border:1px solid #1e2e1e;border-radius:8px;padding:16px;margin-bottom:20px;">
          <p style="font-size:11px;color:#6b8f6b;margin:0 0 6px;text-transform:uppercase;letter-spacing:0.1em;">Reviewed URL</p>
          <p style="font-family:monospace;font-size:13px;color:#9ca3af;margin:0;word-break:break-all;">{url}</p>
        </div>
        <div style="background:#0f172a;border:1px solid #1e3a5f;border-radius:8px;padding:14px;">
          <p style="font-size:13px;color:#93c5fd;margin:0;line-height:1.6;">
            🔍 If you still believe this site is dangerous, you can resubmit with a screenshot.<br>
            🙏 We appreciate you helping protect the community!
          </p>
        </div>
      </div>
      <div style="padding:16px 32px;border-top:1px solid #1e2e1e;text-align:center;">
        <p style="font-size:11px;color:#4b5563;margin:0;">PhishDect · <a href="https://phishdect.ddns.net" style="color:#22c55e;">phishdect.ddns.net</a></p>
      </div>
    </div>
    """
    return send_email(to_email, subject, html)
