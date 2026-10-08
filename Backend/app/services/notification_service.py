import os
import sys
import re
import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

import httpx

from app.config import settings

logger = logging.getLogger("cyberscope.notifications")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def _is_test_mode() -> bool:
    """
    Determines if the application is running in an automated test environment
    or has mock dispatch explicitly enabled.
    """
    return (
        settings.VERIFICATION_MOCK_DISPATCH
        or "pytest" in sys.modules
        or os.environ.get("PYTEST_CURRENT_TEST") is not None
        or settings.APP_ENV in ("test", "testing")
    )


class EmailDispatcher:
    """
    Handles cryptographic dispatch of verification codes and forensic notifications
    via enterprise SMTP with fallback to an in-memory testing outbox.
    """

    def __init__(self):
        self.dispatched_emails: List[Dict[str, Any]] = []

    def _build_html_template(self, recipient_name: str, code: str) -> str:
        name = recipient_name.strip() if recipient_name else "Investigator"
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CyberScope Security Verification</title>
</head>
<body style="margin: 0; padding: 0; background-color: #080d1a; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #e2e8f0;">
  <table role="presentation" width="100%" border="0" cellspacing="0" cellpadding="0" style="background-color: #080d1a; padding: 40px 10px;">
    <tr>
      <td align="center">
        <!-- Main Container -->
        <table role="presentation" width="100%" max-width="600" style="max-width: 600px; background: linear-gradient(180deg, #0f172a 0%, #0a0f1d 100%); border: 1px solid #1e293b; border-radius: 12px; overflow: hidden; box-shadow: 0 20px 40px rgba(0, 0, 0, 0.6);">
          
          <!-- Top Neon Accent Header Bar -->
          <tr>
            <td style="height: 4px; background: linear-gradient(90deg, #00f0ff 0%, #00ff9d 50%, #3b82f6 100%);"></td>
          </tr>

          <!-- Brand Header -->
          <tr>
            <td style="padding: 32px 36px 20px; text-align: left;">
              <table role="presentation" width="100%" border="0" cellspacing="0" cellpadding="0">
                <tr>
                  <td>
                    <div style="font-size: 24px; font-weight: 800; letter-spacing: 2px; color: #00f0ff; text-transform: uppercase;">
                      CYBERSCOPE
                    </div>
                    <div style="font-size: 11px; font-weight: 600; letter-spacing: 1.5px; color: #64748b; text-transform: uppercase; margin-top: 4px;">
                      Financial Forensics &amp; Threat Intelligence
                    </div>
                  </td>
                  <td align="right" valign="top">
                    <span style="display: inline-block; padding: 4px 10px; font-size: 10px; font-weight: 700; letter-spacing: 1px; color: #00ff9d; background: rgba(0, 255, 157, 0.1); border: 1px solid rgba(0, 255, 157, 0.3); border-radius: 4px; text-transform: uppercase;">
                      SECURITY NOTIFICATION
                    </span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Content Body -->
          <tr>
            <td style="padding: 10px 36px 24px;">
              <p style="font-size: 15px; line-height: 1.6; color: #cbd5e1; margin: 0 0 16px;">
                Hello <strong style="color: #f8fafc;">{name}</strong>,
              </p>
              <p style="font-size: 14px; line-height: 1.6; color: #94a3b8; margin: 0 0 24px;">
                A request has been initiated to verify your investigator identity on the CyberScope Intelligence Platform. Use the one-time security authentication code below to finalize your registration:
              </p>

              <!-- Prominent Monospace Code Box -->
              <table role="presentation" width="100%" border="0" cellspacing="0" cellpadding="0" style="margin: 28px 0;">
                <tr>
                  <td align="center" style="background: rgba(0, 240, 255, 0.04); border: 1px dashed rgba(0, 240, 255, 0.4); border-radius: 8px; padding: 24px 20px;">
                    <div style="font-size: 11px; font-weight: 700; letter-spacing: 2px; color: #38bdf8; text-transform: uppercase; margin-bottom: 8px;">
                      Authentication Security Code
                    </div>
                    <div style="font-family: 'Courier New', Courier, monospace; font-size: 40px; font-weight: 800; letter-spacing: 14px; color: #00f0ff; text-align: center; text-indent: 14px;">
                      {code}
                    </div>
                    <div style="font-size: 11px; color: #64748b; margin-top: 10px;">
                      6-Digit Cryptographic Verification PIN
                    </div>
                  </td>
                </tr>
              </table>

              <!-- Expiry Alert -->
              <div style="background: rgba(245, 158, 11, 0.08); border-left: 3px solid #f59e0b; border-radius: 4px; padding: 12px 16px; margin-bottom: 24px;">
                <p style="margin: 0; font-size: 13px; line-height: 1.5; color: #fbbf24;">
                  <strong>Expiration Notice:</strong> This authentication code is valid for exactly <strong>10 minutes</strong>. After expiration, a new code must be generated.
                </p>
              </div>

              <!-- Security Advice -->
              <div style="background: #111827; border: 1px solid #1f2937; border-radius: 6px; padding: 14px 18px; margin-bottom: 20px;">
                <p style="margin: 0; font-size: 12px; line-height: 1.6; color: #94a3b8;">
                  <strong style="color: #cbd5e1;">Security Protocol:</strong> CyberScope officers and automated systems will never request your verification PIN or password via phone, email, or direct messaging. Never share this code with anyone.
                </p>
              </div>

              <p style="font-size: 12px; line-height: 1.5; color: #64748b; margin: 0;">
                If you did not initiate this registration request, no action is required; the code will expire automatically. You may report unauthorized attempts to your agency security administrator.
              </p>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding: 24px 36px 32px; border-top: 1px solid #1e293b; background-color: #090e1a;">
              <table role="presentation" width="100%" border="0" cellspacing="0" cellpadding="0">
                <tr>
                  <td style="font-size: 11px; color: #475569; line-height: 1.5;">
                    &copy; 2026 CyberScope Intelligence Network. All rights reserved.<br>
                    Autonomous Forensic Dispatch Engine &bull; Zero Trust Identity Verification
                  </td>
                </tr>
              </table>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

    def _build_plain_text(self, recipient_name: str, code: str) -> str:
        name = recipient_name.strip() if recipient_name else "Investigator"
        return f"""=======================================================
CYBERSCOPE INTELLIGENCE PLATFORM
OFFICIAL IDENTITY VERIFICATION DISPATCH
=======================================================

Hello {name},

A registration request was submitted to access the CyberScope
Forensics & Financial Crime Intelligence Platform.

Your 6-digit verification code is:

    >>> {code} <<<

SECURITY NOTICE:
- Valid for exactly 10 minutes.
- CyberScope personnel will NEVER ask you for this code.
- Do not disclose this code to anyone.

If you did not initiate this request, no action is needed;
the verification code will expire automatically.

=======================================================
CyberScope Security Operations
https://cyberscope.io
=======================================================
"""

    def send_verification_email(self, to_email: str, recipient_name: str, code: str) -> Dict[str, Any]:
        """
        Constructs and dispatches a verification email.
        Uses SMTP when configured; otherwise cleanly logs and stores in the test outbox.
        """
        to_email = to_email.strip().lower()
        subject = f"CyberScope Verification Code: {code}"

        # Build multipart message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        sender_header = (
            f"{settings.SMTP_FROM_NAME} <{settings.SMTP_FROM_EMAIL}>"
            if settings.SMTP_FROM_NAME
            else settings.SMTP_FROM_EMAIL
        )
        msg["From"] = sender_header
        msg["To"] = to_email

        plain_text = self._build_plain_text(recipient_name, code)
        html_content = self._build_html_template(recipient_name, code)

        msg.attach(MIMEText(plain_text, "plain", "utf-8"))
        msg.attach(MIMEText(html_content, "html", "utf-8"))

        # Check if automated test mode (unless explicitly forced via _FORCE_LIVE_SMTP)
        is_test = _is_test_mode() and not getattr(settings, "_FORCE_LIVE_SMTP", False)
        if is_test:
            record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "to_email": to_email,
                "recipient_name": recipient_name,
                "code": code,
                "subject": subject,
                "plain_text": plain_text,
                "html_content": html_content
            }
            self.dispatched_emails.append(record)
            logger.info(f"[EmailDispatcher:mock] Verification email recorded in test outbox for {to_email}")
            return {
                "success": True,
                "provider": "mock",
                "message": f"Verification email recorded in test outbox for {to_email}."
            }

        # If not in test mode, check if SMTP credentials are configured
        if not (settings.SMTP_HOST and settings.SMTP_USER and settings.SMTP_PASSWORD):
            logger.warning(f"[EmailDispatcher:unconfigured] SMTP is not configured in .env. Email to {to_email} could not be sent.")
            return {
                "success": False,
                "provider": "unconfigured_smtp",
                "message": "SMTP credentials not configured in .env. Please set SMTP_HOST, SMTP_PORT, SMTP_USER, and SMTP_PASSWORD."
            }

        # Real SMTP Dispatch
        try:
            timeout = settings.SMTP_TIMEOUT_SECONDS
            if settings.SMTP_USE_SSL:
                server = smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT, timeout=timeout)
            else:
                server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=timeout)
                if settings.SMTP_USE_TLS:
                    server.starttls()

            if settings.SMTP_USER and settings.SMTP_PASSWORD:
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)

            server.send_message(msg)
            server.quit()
            logger.info(f"[EmailDispatcher:SMTP] Real verification email successfully sent to {to_email}")
            return {
                "success": True,
                "provider": "smtp",
                "message": f"Verification email dispatched to {to_email}."
            }
        except Exception as exc:
            logger.error(f"[EmailDispatcher:SMTP] Failed to send email to {to_email}: {exc}")
            return {
                "success": False,
                "provider": "smtp",
                "message": f"SMTP dispatch failed: {str(exc)}"
            }


class SmsDispatcher:
    """
    Handles SMS verification dispatch with multi-provider failover:
    Supports Twilio, Fast2SMS, custom Webhook, and in-memory test recording.
    """

    def __init__(self):
        self.dispatched_sms: List[Dict[str, Any]] = []

    def send_verification_sms(self, to_phone: str, code: str) -> Dict[str, Any]:
        """
        Dispatches a 6-digit OTP code to the recipient's phone number.
        """
        to_phone = to_phone.strip()
        message = f"Your CyberScope verification code is: {code}. Valid for 10 minutes. Do not share this code."
        provider = settings.SMS_PROVIDER.lower() if settings.SMS_PROVIDER else "twilio"

        # Check if automated test mode (unless explicitly forced via _FORCE_LIVE_SMS)
        is_test = _is_test_mode() and not getattr(settings, "_FORCE_LIVE_SMS", False)
        if is_test:
            record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "to_phone": to_phone,
                "code": code,
                "message": message,
                "provider": "mock"
            }
            self.dispatched_sms.append(record)
            logger.info(f"[SmsDispatcher:mock] Verification SMS recorded in test outbox for {to_phone}")
            return {
                "success": True,
                "provider": "mock",
                "message": f"Verification SMS recorded in test outbox for {to_phone}."
            }

        # Provider: Twilio
        if provider == "twilio":
            account_sid = settings.TWILIO_ACCOUNT_SID
            auth_token = settings.TWILIO_AUTH_TOKEN
            from_num = settings.TWILIO_FROM_NUMBER
            messaging_service_sid = settings.TWILIO_MESSAGING_SERVICE_SID

            if not (account_sid and auth_token and (from_num or messaging_service_sid)):
                logger.warning(f"[SmsDispatcher:unconfigured] Twilio SMS credentials missing in .env. SMS to {to_phone} not sent.")
                return {
                    "success": False,
                    "provider": "unconfigured_twilio",
                    "message": "Twilio SMS credentials not configured in .env. Please configure TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and TWILIO_FROM_NUMBER."
                }

            url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
            data: Dict[str, str] = {
                "To": to_phone,
                "Body": message
            }
            if from_num:
                data["From"] = from_num
            elif messaging_service_sid:
                data["MessagingServiceSid"] = messaging_service_sid

            try:
                with httpx.Client(timeout=10.0) as client:
                    resp = client.post(url, auth=(account_sid, auth_token), data=data)
                    if resp.status_code in (200, 201):
                        logger.info(f"[SmsDispatcher:Twilio] SMS dispatched to {to_phone}")
                        return {
                            "success": True,
                            "provider": "twilio",
                            "message": f"Verification SMS sent via Twilio to {to_phone}."
                        }
                    logger.error(f"[SmsDispatcher:Twilio] Twilio returned HTTP {resp.status_code}: {resp.text}")
                    return {
                        "success": False,
                        "provider": "twilio",
                        "message": f"Twilio SMS delivery failed (HTTP {resp.status_code}): {resp.text}"
                    }
            except Exception as exc:
                logger.error(f"[SmsDispatcher:Twilio] Exception during dispatch: {exc}")
                return {
                    "success": False,
                    "provider": "twilio",
                    "message": f"Twilio dispatch error: {str(exc)}"
                }

        # Provider: Fast2SMS
        if provider == "fast2sms":
            key = settings.FAST2SMS_API_KEY
            if not key:
                logger.warning(f"[SmsDispatcher:unconfigured] Fast2SMS API key missing in .env. SMS to {to_phone} not sent.")
                return {
                    "success": False,
                    "provider": "unconfigured_fast2sms",
                    "message": "Fast2SMS API key not configured in .env. Please configure FAST2SMS_API_KEY."
                }

            # Extract clean 10-digit number for Fast2SMS Indian gateway
            phone_digits = re.sub(r"\D", "", to_phone)
            if len(phone_digits) > 10:
                phone_digits = phone_digits[-10:]

            url = "https://www.fast2sms.com/dev/bulkV2"
            headers = {
                "authorization": key,
                "Content-Type": "application/json"
            }
            payload = {
                "route": "otp",
                "variables_values": code,
                "numbers": phone_digits
            }

            try:
                with httpx.Client(timeout=10.0) as client:
                    resp = client.post(url, headers=headers, json=payload)
                    if resp.status_code == 200:
                        res_data = resp.json()
                        if res_data.get("return") is True:
                            logger.info(f"[SmsDispatcher:Fast2SMS] OTP dispatched to {phone_digits}")
                            return {
                                "success": True,
                                "provider": "fast2sms",
                                "message": f"Verification SMS sent via Fast2SMS to {to_phone}."
                            }
                        return {
                            "success": False,
                            "provider": "fast2sms",
                            "message": f"Fast2SMS rejected dispatch: {res_data.get('message', 'Unknown error')}"
                        }
                    return {
                        "success": False,
                        "provider": "fast2sms",
                        "message": f"Fast2SMS returned HTTP {resp.status_code}: {resp.text}"
                    }
            except Exception as exc:
                logger.error(f"[SmsDispatcher:Fast2SMS] Exception: {exc}")
                return {
                    "success": False,
                    "provider": "fast2sms",
                    "message": f"Fast2SMS dispatch error: {str(exc)}"
                }

        # Provider: Webhook
        if provider == "webhook":
            url = settings.SMS_WEBHOOK_URL
            if not url:
                return {
                    "success": False,
                    "provider": "unconfigured_webhook",
                    "message": "SMS Webhook URL not configured in .env. Please configure SMS_WEBHOOK_URL."
                }
            payload = {
                "to": to_phone,
                "code": code,
                "message": message
            }
            try:
                with httpx.Client(timeout=10.0) as client:
                    resp = client.post(url, json=payload)
                    if resp.status_code in (200, 201, 202, 204):
                        logger.info(f"[SmsDispatcher:Webhook] Dispatched SMS payload to {url}")
                        return {
                            "success": True,
                            "provider": "webhook",
                            "message": f"Verification SMS dispatched via Webhook to {to_phone}."
                        }
                    return {
                        "success": False,
                        "provider": "webhook",
                        "message": f"Webhook returned HTTP {resp.status_code}: {resp.text}"
                    }
            except Exception as exc:
                logger.error(f"[SmsDispatcher:Webhook] Exception: {exc}")
                return {
                    "success": False,
                    "provider": "webhook",
                    "message": f"Webhook dispatch error: {str(exc)}"
                }

        # Unconfigured / Mock outside test environment
        logger.warning(f"[SmsDispatcher:unconfigured] SMS provider '{provider}' credentials are not configured in .env.")
        return {
            "success": False,
            "provider": f"unconfigured_{provider}",
            "message": f"SMS provider '{provider}' credentials are not configured in .env. Please set TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and TWILIO_FROM_NUMBER or FAST2SMS_API_KEY."
        }


class NotificationService:
    """
    Singleton facade providing unified email and SMS verification dispatch
    capabilities across the CyberScope platform.
    """

    def __init__(self):
        self.email_dispatcher = EmailDispatcher()
        self.sms_dispatcher = SmsDispatcher()

    def send_verification_email(self, to_email: str, recipient_name: str, code: str) -> Dict[str, Any]:
        """
        Sends an official verification email with branded HTML and plain-text fallback.
        """
        return self.email_dispatcher.send_verification_email(to_email, recipient_name, code)

    def send_verification_sms(self, to_phone: str, code: str) -> Dict[str, Any]:
        """
        Sends a verification SMS containing the 6-digit OTP code.
        """
        return self.sms_dispatcher.send_verification_sms(to_phone, code)

    def get_test_outbox(self) -> Dict[str, Any]:
        """
        Retrieves all dispatched emails and SMS records in the in-memory test outbox.
        Useful for automated testing and CI verification.
        """
        return {
            "emails": list(self.email_dispatcher.dispatched_emails),
            "sms": list(self.sms_dispatcher.dispatched_sms),
        }

    def clear_test_outbox(self) -> None:
        """
        Clears the in-memory test outbox.
        """
        self.email_dispatcher.dispatched_emails.clear()
        self.sms_dispatcher.dispatched_sms.clear()

    @property
    def dispatched_emails(self) -> List[Dict[str, Any]]:
        return self.email_dispatcher.dispatched_emails

    @property
    def dispatched_sms(self) -> List[Dict[str, Any]]:
        return self.sms_dispatcher.dispatched_sms


notification_service = NotificationService()
