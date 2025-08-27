# api.py
from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse
import os, asyncio
from verifier import verify_email_address

# read concurrency + timeout from env (with defaults)
CONCURRENCY = int(os.getenv("CONCURRENCY", "50"))
SMTP_TIMEOUT = float(os.getenv("SMTP_TIMEOUT", "3"))

app = FastAPI(title="Email Verifier API", version="0.1.0")

@app.post("/verify-batch")
async def verify_batch(payload: dict):
    emails = payload.get("emails", [])
    emails = [e for e in emails if isinstance(e, str)]

    sem = asyncio.Semaphore(CONCURRENCY)

    async def one(e):
        async with sem:
            try:
                return await asyncio.wait_for(verify_email_address(e), timeout=SMTP_TIMEOUT + 1.0)
            except asyncio.TimeoutError:
                return {"input": e, "deliverable": False, "smtp_accepts": None, "is_catch_all": None, "reason": ["timeout"]}

    results = await asyncio.gather(*(one(e) for e in emails))
    return JSONResponse({"results": results})
