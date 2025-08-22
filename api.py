from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
import asyncio
from verifier import verify_email_address

app = FastAPI(title="Email Verifier API", version="0.1.0")

@app.get("/verify")
async def verify(email: str = Query(..., description="email to verify")):
    result = await verify_email_address(email)
    return JSONResponse(result)

@app.post("/verify-batch")
async def verify_batch(payload: dict):
    emails = payload.get("emails", [])
    emails = [e for e in emails if isinstance(e, str)]
    results = []
    for e in emails:
        results.append(await verify_email_address(e))
    return JSONResponse({"results": results})
