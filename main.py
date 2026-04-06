from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from pydantic import BaseModel
from twilio.rest import Client
from twilio.jwt.access_token import AccessToken
from twilio.jwt.access_token.grants import VoiceGrant
from twilio.twiml.voice_response import VoiceResponse, Dial
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

# ── Twilio credentials from .env ──────────────────────────────────────────────
ACCOUNT_SID        = os.getenv("TWILIO_ACCOUNT_SID")
API_KEY            = os.getenv("TWILIO_API_KEY")
API_SECRET         = os.getenv("TWILIO_API_SECRET")
TWIML_APP_SID      = os.getenv("TWILIO_TWIML_APP_SID")
TWILIO_NUMBER      = os.getenv("TWILIO_NUMBER")          # e.g. +12345678900
CLIENT_IDENTITY    = os.getenv("CLIENT_IDENTITY", "browser_user")
PUBLIC_BASE_URL    = os.getenv("PUBLIC_BASE_URL", "")

# ── Single-user auth credentials from .env ──────────────────────────────────
APP_USERNAME       = os.getenv("APP_USERNAME", "admin")
APP_PASSWORD       = os.getenv("APP_PASSWORD", "admin123")
JWT_SECRET         = os.getenv("JWT_SECRET", "change_this_secret_in_env")
JWT_ALGORITHM      = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "720"))

TWILIO_CLIENT = Client(API_KEY, API_SECRET, ACCOUNT_SID)
security = HTTPBearer(auto_error=False)

# Runtime logs are kept in memory; frontend stores local snapshots in localStorage.
CALL_LOGS: List[Dict[str, Any]] = []
SMS_LOGS: List[Dict[str, Any]] = []
TRANSCRIPTION_LOGS: List[Dict[str, Any]] = []


class LoginRequest(BaseModel):
    username: str
    password: str


class SMSRequest(BaseModel):
    to: str
    body: str


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_log(store: List[Dict[str, Any]], payload: Dict[str, Any]) -> None:
    payload["logged_at"] = utc_now()
    store.append(payload)
    if len(store) > 300:
        del store[0: len(store) - 300]


def build_callback_url(path: str, request: Request | None = None) -> str:
    if PUBLIC_BASE_URL:
        return f"{PUBLIC_BASE_URL.rstrip('/')}/{path.lstrip('/')}"
    if request is not None:
        return str(request.base_url).rstrip("/") + "/" + path.lstrip("/")
    raise ValueError("PUBLIC_BASE_URL is required when request context is unavailable")


def create_jwt_token(username: str) -> str:
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES)
    claims = {
        "sub": username,
        "exp": expires_at,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(claims, JWT_SECRET, algorithm=JWT_ALGORITHM)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> str:
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
        )

    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        ) from exc

    username = payload.get("sub")
    if username != APP_USERNAME:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized account",
        )
    return username


@app.post("/auth/login")
async def login(payload: LoginRequest):
    if payload.username != APP_USERNAME or payload.password != APP_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    token = create_jwt_token(payload.username)
    return JSONResponse({"access_token": token, "token_type": "bearer"})


@app.get("/auth/me")
async def auth_me(current_user: str = Depends(get_current_user)):
    return JSONResponse({"username": current_user})


# ── 1. Serve the frontend ─────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index():
    with open("static/index.html", encoding="utf-8") as f:
        return f.read()


# ── 2. Issue Access Token to the browser ─────────────────────────────────────
@app.get("/token")
async def get_token(current_user: str = Depends(get_current_user)):
    token = AccessToken(
        ACCOUNT_SID,
        API_KEY,
        API_SECRET,
        identity=current_user,
        ttl=3600            # token valid for 1 hour
    )

    grant = VoiceGrant(
        outgoing_application_sid=TWIML_APP_SID,
        incoming_allow=True             # allow browser to receive calls too
    )
    token.add_grant(grant)

    return JSONResponse({"token": token.to_jwt(), "identity": current_user})


# ── 3. TwiML – Twilio calls this when browser makes / receives a call ─────────
@app.post("/voice")
@app.post("/api/v1/communications/calls/voice")
async def voice(request: Request):
    form   = await request.form()
    to     = form.get("To", "")        # phone number the user wants to call
    from_  = form.get("From", "")

    response = VoiceResponse()
    # Twilio inbound webhooks include a "To" number as well, so we detect
    # browser-originated calls by checking if "From" is a client identity.
    is_browser_originated = from_.startswith("client:")

    status_callback_url = build_callback_url("/voice/status", request)

    if is_browser_originated and to:
        # ── Outbound: browser → phone number / client ──────────────────────
        dial = Dial(
            caller_id=TWILIO_NUMBER,
            status_callback=status_callback_url,
            status_callback_event=["initiated", "ringing", "answered", "completed"],
            status_callback_method="POST",
            record="record-from-answer",
            recording_status_callback=build_callback_url("/voice/transcription", request),
            recording_status_callback_method="POST",
        )
        if to.startswith("client:"):
            dial.client(to.replace("client:", ""))
        else:
            dial.number(to)
        response.append(dial)

        append_log(
            CALL_LOGS,
            {
                "event": "outbound_request",
                "from": from_,
                "to": to,
            },
        )
    else:
        # ── Inbound: phone → browser ───────────────────────────────────────
        dial = Dial(
            status_callback=status_callback_url,
            status_callback_event=["initiated", "ringing", "answered", "completed"],
            status_callback_method="POST",
            record="record-from-answer",
            recording_status_callback=build_callback_url("/voice/transcription", request),
            recording_status_callback_method="POST",
        )
        dial.client(APP_USERNAME)
        response.append(dial)

        append_log(
            CALL_LOGS,
            {
                "event": "inbound_request",
                "from": from_,
                "to": CLIENT_IDENTITY,
            },
        )

    return HTMLResponse(content=str(response), media_type="application/xml")


@app.post("/voice/status")
async def voice_status_callback(request: Request):
    form = await request.form()
    append_log(
        CALL_LOGS,
        {
            "event": "call_status",
            "call_sid": form.get("CallSid"),
            "parent_call_sid": form.get("ParentCallSid"),
            "call_status": form.get("CallStatus"),
            "direction": form.get("Direction"),
            "from": form.get("From"),
            "to": form.get("To"),
            "duration": form.get("CallDuration"),
        },
    )
    return JSONResponse({"ok": True})


@app.post("/voice/transcription")
async def voice_transcription_callback(request: Request):
    form = await request.form()
    append_log(
        TRANSCRIPTION_LOGS,
        {
            "event": "voice_transcription",
            "call_sid": form.get("CallSid"),
            "recording_sid": form.get("RecordingSid"),
            "transcription_text": form.get("TranscriptionText"),
            "transcription_status": form.get("TranscriptionStatus"),
        },
    )
    return JSONResponse({"ok": True})


@app.post("/sms/send")
async def send_sms(
    payload: SMSRequest,
    request: Request,
    current_user: str = Depends(get_current_user),
):
    try:
        message = TWILIO_CLIENT.messages.create(
            to=payload.to,
            from_=TWILIO_NUMBER,
            body=payload.body,
            status_callback=build_callback_url("/sms/status", request),
        )
    except Exception as exc:
        append_log(
            SMS_LOGS,
            {
                "event": "sms_send_error",
                "to": payload.to,
                "error": str(exc),
                "requested_by": current_user,
            },
        )
        raise HTTPException(status_code=400, detail=f"SMS failed: {exc}") from exc

    append_log(
        SMS_LOGS,
        {
            "event": "sms_sent",
            "sid": message.sid,
            "to": message.to,
            "from": message.from_,
            "status": message.status,
            "body": payload.body,
            "requested_by": current_user,
        },
    )

    return JSONResponse(
        {
            "sid": message.sid,
            "status": message.status,
            "to": message.to,
            "from": message.from_,
        }
    )


@app.post("/sms/status")
async def sms_status_callback(request: Request):
    form = await request.form()
    append_log(
        SMS_LOGS,
        {
            "event": "sms_status",
            "sid": form.get("MessageSid"),
            "message_status": form.get("MessageStatus"),
            "to": form.get("To"),
            "from": form.get("From"),
            "error_code": form.get("ErrorCode"),
            "error_message": form.get("ErrorMessage"),
        },
    )
    return JSONResponse({"ok": True})


@app.post("/sms/inbound")
async def sms_inbound_callback(request: Request):
    form = await request.form()
    payload = dict(form)
    inbound_body = (
        payload.get("Body")
        or payload.get("body")
        or payload.get("SmsBody")
        or payload.get("MessageBody")
        or ""
    )

    # Some inbound messages may be media-only and carry no text body.
    if not inbound_body and str(payload.get("NumMedia", "0")) != "0":
        inbound_body = "[media message: no text body]"

    append_log(
        SMS_LOGS,
        {
            "event": "sms_inbound",
            "sid": payload.get("MessageSid") or payload.get("SmsSid"),
            "from": payload.get("From"),
            "to": payload.get("To"),
            "body": inbound_body,
            "num_media": payload.get("NumMedia"),
            "sms_status": payload.get("SmsStatus"),
            "payload_keys": sorted(list(payload.keys())),
        },
    )
    return JSONResponse({"ok": True})


@app.get("/api/server-logs")
async def server_logs(current_user: str = Depends(get_current_user)):
    return JSONResponse(
        {
            "username": current_user,
            "calls": CALL_LOGS[-100:],
            "sms": SMS_LOGS[-100:],
            "transcriptions": TRANSCRIPTION_LOGS[-100:],
        }
    )


# ── Mount static files ────────────────────────────────────────────────────────
app.mount("/static", StaticFiles(directory="static"), name="static")
