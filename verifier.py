# verifier.py
import asyncio, random, string
from typing import Dict, Optional
import dns.resolver
from email_validator import validate_email, EmailNotValidError
import aiosmtplib

ROLE_PREFIXES = {
    "admin","administrator","billing","contact","dev","dns","enquiry","finance","help","hello","hr",
    "info","it","jobs","marketing","news","noreply","no-reply","office","postmaster","root","sales",
    "security","service","staff","support","team","webmaster"
}

DISPOSABLE = set(d.strip() for d in """
mailinator.com
yopmail.com
temp-mail.org
guerillamail.com
10minutemail.com
trashmail.com
sharklasers.com
""".splitlines() if d.strip())

SMTP_PORTS = [25, 587]

async def has_mx(domain: str) -> bool:
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=3)
        return len(answers) > 0
    except Exception:
        return False

async def is_catch_all(domain: str, mx_hosts: list, timeout: float = 12.0) -> Optional[bool]:
    """
    Try multiple random addresses across multiple MX hosts.
    Return True if any RCPT is accepted, False if all RCPT are rejected,
    None if every attempt is inconclusive (timeouts/4xx).
    """
    outcomes = []
    tries = 3  # random addresses
    mx_to_try = mx_hosts[:2]  # first two MX records

    for _ in range(tries):
        probe_addr = f"{random_local(16)}@{domain}"
        for mx in mx_to_try:
            ok = await smtp_check(probe_addr, mx, timeout=timeout)
            # short-circuit on a definite accept
            if ok is True:
                return True
            outcomes.append(ok)

    if any(o is False for o in outcomes):
        return False
    if all(o is None for o in outcomes):
        return None
    return None
    
