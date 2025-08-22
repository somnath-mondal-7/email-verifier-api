import asyncio
import random
import string
from typing import Dict, Optional

import dns.resolver
from email_validator import validate_email, EmailNotValidError
import aiosmtplib

ROLE_PREFIXES = {
    "admin","administrator","billing","contact","dev","dns","enquiry",
    "finance","help","hello","hr","info","it","jobs","marketing",
    "news","noreply","no-reply","office","postmaster","root","sales",
    "security","service","staff","support","team","webmaster"
}

DISPOSABLE = {
    "mailinator.com","yopmail.com","temp-mail.org","guerillamail.com",
    "10minutemail.com","trashmail.com","sharklasers.com"
}

SMTP_PORTS = [25, 587]

async def has_mx(domain: str) -> bool:
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=3)
        return len(answers) > 0
    except Exception:
        return False

async def smtp_check(rcpt: str, mx_host: str, helo_domain: str = "example.com", timeout: float = 6.0) -> Optional[bool]:
    """True=accepts, False=rejects, None=inconclusive"""
    for port in SMTP_PORTS:
        try:
            client = aiosmtplib.SMTP(hostname=mx_host, port=port, timeout=timeout)
            await client.connect()
            try:
                await client.ehlo()
            except Exception:
                try:
                    await client.helo()
                except Exception:
                    pass
            try:
                await client.mail(f"<verify@{helo_domain}>")
                code, _ = await client.rcpt(f"<{rcpt}>")
                await client.quit()
                if 200 <= code < 300:
                    return True
                if 500 <= code < 600:
                    return False
                return None
            except Exception:
                try:
                    await client.quit()
                except Exception:
                    pass
        except Exception:
            continue
    return None

def is_role(local: str) -> bool:
    return local.lower() in ROLE_PREFIXES

def random_local(n: int = 12) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))

async def verify_email_address(email: str) -> Dict:
    result = {
        "input": email,
        "is_valid_syntax": False,
        "has_mx": False,
        "is_disposable": False,
        "is_role": False,
        "smtp_accepts": None,
        "is_catch_all": None,
        "deliverable": False,
        "reason": [],
    }

    # 1) Syntax
    try:
        info = validate_email(email, check_deliverability=False)
        email_norm = info.normalized
        local, domain = email_norm.split("@", 1)
        result["is_valid_syntax"] = True
    except EmailNotValidError as e:
        result["reason"].append(f"syntax:{str(e)}")
        return result

    # 2) Disposable/Role
    result["is_disposable"] = domain.lower() in DISPOSABLE
    result["is_role"] = is_role(local)

    # 3) MX
    result["has_mx"] = await has_mx(domain)
    if not result["has_mx"]:
        result["reason"].append("no_mx")
        return result

    # Get MX hosts
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=3)
        hosts = [str(r.exchange).rstrip('.') for r in sorted(answers, key=lambda r: r.preference)]
    except Exception:
        hosts = []

    # 4) SMTP accept?
    smtp_outcomes = []
    for mx in hosts[:2]:
        ok = await smtp_check(email, mx)
        smtp_outcomes.append(ok)
        if ok is True:
            break

    smtp_signal = next((o for o in smtp_outcomes if o is True), None)
    if smtp_signal is None and any(o is False for o in smtp_outcomes):
        smtp_signal = False
    result["smtp_accepts"] = smtp_signal

    # 5) Catch-all probe
    if hosts and not result["is_disposable"]:
        probe = f"{random_local()}@{domain}"
        catch = await smtp_check(probe, hosts[0])
        result["is_catch_all"] = True if catch else (False if catch is False else None)

    # Final decision
    deliverable = (
        result["is_valid_syntax"]
        and result["has_mx"]
        and not result["is_disposable"]
        and (result["smtp_accepts"] is True or (result["smtp_accepts"] is None and result["is_catch_all"] is False))
    )
    result["deliverable"] = deliverable

    if result["is_disposable"]:
        result["reason"].append("disposable")
    if result["is_role"]:
        result["reason"].append("role")
    if result["smtp_accepts"] is False:
        result["reason"].append("smtp_reject")
    if result["is_catch_all"] is True:
        result["reason"].append("catch_all")

    return result
