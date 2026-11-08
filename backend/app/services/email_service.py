import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from typing import List, Dict, Any, Optional

from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# In-memory store for mock provider (used in automated tests)
mock_sent_emails: List[Dict[str, Any]] = []


class EmailService:
    def __init__(self):
        self.provider = (settings.EMAIL_PROVIDER or "console").lower()
        self.email_from = settings.EMAIL_FROM
        self.frontend_url = settings.FRONTEND_URL.rstrip("/") if settings.FRONTEND_URL else "http://localhost:5173"

    def send_verification_email(self, to_email: str, raw_token: str, full_name: Optional[str] = None) -> bool:
        """
        Sends an email verification link using the configured provider.
        Link format: {frontend_url}/verify-email?token={raw_token}
        """
        verification_link = f"{self.frontend_url}/verify-email?token={raw_token}"
        subject = "Verify your ITDR Platform Account"
        user_display = full_name or to_email.split("@")[0]

        plain_content = (
            f"Hello {user_display},\n\n"
            f"Thank you for registering for the ITDR RAG Platform Demo.\n\n"
            f"Please verify your email address by opening the following link:\n"
            f"{verification_link}\n\n"
            f"This link will expire in {settings.EMAIL_VERIFICATION_EXPIRE_MINUTES} minutes.\n\n"
            f"If you did not register for this account, please ignore this email.\n\n"
            f"— The ITDR Security Team"
        )

        html_content = f"""
        <html>
            <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b1120; color: #e2e8f0; padding: 24px;">
                <div style="max-width: 560px; margin: 0 auto; background-color: #1e293b; border-radius: 8px; border: 1px solid #334155; padding: 32px;">
                    <h2 style="color: #38bdf8; margin-top: 0;">Verify your ITDR Platform Account</h2>
                    <p style="color: #94a3b8; font-size: 15px; line-height: 1.6;">Hello <strong>{user_display}</strong>,</p>
                    <p style="color: #94a3b8; font-size: 15px; line-height: 1.6;">
                        Thank you for registering for the ITDR RAG Platform Demo. Please click the button below to verify your email address and activate your demo analyst account:
                    </p>
                    <div style="text-align: center; margin: 32px 0;">
                        <a href="{verification_link}" style="background-color: #0284c7; color: #ffffff; padding: 12px 28px; text-decoration: none; border-radius: 6px; font-weight: 600; display: inline-block;">
                            Verify Email Address
                        </a>
                    </div>
                    <p style="color: #64748b; font-size: 13px; line-height: 1.5;">
                        Or copy and paste this URL into your browser:<br/>
                        <a href="{verification_link}" style="color: #38bdf8; word-break: break-all;">{verification_link}</a>
                    </p>
                    <p style="color: #64748b; font-size: 12px; margin-top: 24px; border-top: 1px solid #334155; padding-top: 16px;">
                        This verification link will expire in {settings.EMAIL_VERIFICATION_EXPIRE_MINUTES} minutes. If you did not create an account, you can safely ignore this email.
                    </p>
                </div>
            </body>
        </html>
        """

        if self.provider == "mock":
            mock_sent_emails.append({
                "to_email": to_email,
                "token": raw_token,
                "link": verification_link,
                "subject": subject,
                "full_name": full_name,
            })
            logger.info(f"[MOCK EMAIL] Recorded verification email for {to_email}")
            return True

        if self.provider == "smtp":
            try:
                msg = MIMEMultipart("alternative")
                msg["Subject"] = subject
                msg["From"] = self.email_from
                msg["To"] = to_email
                msg.attach(MIMEText(plain_content, "plain"))
                msg.attach(MIMEText(html_content, "html"))

                with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
                    if settings.SMTP_TLS:
                        server.starttls()
                    if settings.SMTP_USER and settings.SMTP_PASSWORD:
                        server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                    server.sendmail(self.email_from, [to_email], msg.as_string())
                logger.info(f"[SMTP EMAIL] Successfully sent verification email to {to_email}")
                return True
            except Exception as e:
                logger.error(f"[SMTP EMAIL] Failed to send email to {to_email}: {e}")
                self._log_console(to_email, verification_link)
                return False

        # Default: console provider
        self._log_console(to_email, verification_link)
        return True

    def _log_console(self, to_email: str, link: str):
        msg = f"\n" + "=" * 70 + f"\n[CONSOLE EMAIL DISPATCH] Verification Link for {to_email}:\n{link}\n" + "=" * 70
        print(msg, flush=True)
        logger.info(f"[CONSOLE EMAIL] Verification link for {to_email}: {link}")


email_service = EmailService()
