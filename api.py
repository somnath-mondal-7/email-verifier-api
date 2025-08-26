# api.py
import os
from typing import Optional, List
from fastapi import FastAPI, Query, Depends, Header, HTTPException
from fastapi.responses import JSONResponse
from verifier import verify_email_address

app = FastAPI(title="Email Verifier API", version="0.2.0")

@app.get("/health")
def health():
    return {"ok": True}

_ALLOWED = {k.strip() for k in os.getenv("API_KEYS", "").split(",") if k.strip()}

def require_api_key(
    x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key"),
    key: Optional[str] = Query(default=None),
):
    if not _ALLOWED:
        raise HTTPException(status_code=503, detail="API key not configured on server")
    supplied = x_api_key or key
    if not supplied or supplied not in _ALLOWED:
        raise HTTPException(status_code=401, detail="Missing/invalid API key")
    return True

@app.get("/verify", dependencies=[Depends(require_api_key)])
async def verify(email: str = Query(..., description="email to verify")):
    result = await verify_email_address(email)
    return JSONResponse(result)

@app.post("/verify-batch", dependencies=[Depends(require_api_key)])
async def verify_batch(payload: dict):
    emails: List[str] = [e for e in payload.get("emails", []) if isinstance(e, str)]
    results = [await verify_email_address(e) for e in emails]
    return JSONResponse({"results": results})
