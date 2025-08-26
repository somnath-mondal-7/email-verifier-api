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

async def smtp_check(rcpt: str, mx_host: str, helo_domain: str = "example.com", timeout: float = 6.0) -> Optional[bool]:
    """True if RCPT accepted, False if rejected, None if inconclusive."""
    for port in SMTP_PORTS:
        try:
            client = aiosmtplib.SMTP(hostname=mx_host, port=port, timeout=timeout)
            await client.connect()
            try:
                await client.ehlo()
            except Exception:
                try: await client.helo()
                except Exception: pass
            try:
                await client.mail(f"<verify@{helo_domain}>")
                code, _ = await client.rcpt(f"<{rcpt}>")
                await client.quit()
                if 200 <= code < 300:  # accepted
                    return True
                if 500 <= code < 600:  # hard reject
                    return False
                return None            # temp/greylist
            except Exception:
                try: await client.quit()
                except Exception: pass
        except Exception:
            continue
    return None

def is_role_account(local: str) -> bool:
    return local.lower() in ROLE_PREFIXES

def rand_local(n=12) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return ''.join(random.choice(alphabet) for _ in range(n))

async def verify_email_address(email: str) -> Dict:
    res = {
        "input": email,
        "is_valid_syntax": False,
        "has_mx": False,
        "is_disposable": False,
        "is_role": False,
        "smtp_accepts": None,
        "is_catch_all": None,
        "deliverable": False,
        "reason": []
    }

    # 1) Syntax
    try:
        info = validate_email(email, check_deliverability=False)
        email = info.normalized
        local, domain = email.split("@", 1)
        res["is_valid_syntax"] = True
    except EmailNotValidError as e:
        res["reason"].append(f"syntax:{e}")
        return res

    # 2) Flags
    res["is_disposable"] = domain.lower() in DISPOSABLE
    res["is_role"] = is_role_account(local)

    # 3) MX
    res["has_mx"] = await has_mx(domain)
    if not res["has_mx"]:
        res["reason"].append("no_mx")
        return res

    # Best MX
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=3)
        mx_hosts = [str(r.exchange).rstrip('.') for r in sorted(answers, key=lambda r: r.preference)]
    except Exception:
        mx_hosts = []

    # 4) RCPT test
    smtp_outcomes = []
    for mx in mx_hosts[:2]:
        ok = await smtp_check(email, mx)
        smtp_outcomes.append(ok)
        if ok is True:
            break

    smtp_signal = next((o for o in smtp_outcomes if o is True), None)
    if smtp_signal is None and any(o is False for o in smtp_outcomes):
        smtp_signal = False
    res["smtp_accepts"] = smtp_signal

    # 5) Catch-all probe (only if we have an MX and a host)
    if mx_hosts:
        probe = f"{rand_local()}@{domain}"
        probe_ok = await smtp_check(probe, mx_hosts[0])
        if probe_ok is True:
            res["is_catch_all"] = True
        elif probe_ok is False:
            res["is_catch_all"] = False
        else:
            res["is_catch_all"] = None

    # Final
    res["deliverable"] = (
        res["is_valid_syntax"] and
        res["has_mx"] and
        not res["is_disposable"] and
        (
            res["smtp_accepts"] is True or
            (res["smtp_accepts"] is None and res["is_catch_all"] is False)
        )
    )
    if res["is_disposable"]: res["reason"].append("disposable")
    if res["is_role"]:        res["reason"].append("role")
    if res["smtp_accepts"] is False: res["reason"].append("smtp_reject")
    if res["is_catch_all"] is True:  res["reason"].append("catch_all")

    return res
