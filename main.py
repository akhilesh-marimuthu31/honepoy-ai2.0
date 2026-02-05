# main.py
"""
main.py - FastAPI app for the Agentic Honey-Pot API

This app accepts incoming scam messages, detects scams, replies with a human-like response,
and extracts intelligence items (UPI IDs, bank accounts, IFSC codes, phishing URLs, card numbers, OTPs).
Requires an API key via the x-api-key header for authentication.
"""
import os
import re
import uuid
import logging
from threading import Lock

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

try:
    import openai
except ImportError:
    openai = None

# Configuration from environment
API_KEY = os.getenv("API_KEY", "my-secret-key-123")
LLM_API_KEY = os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY")
if LLM_API_KEY and openai:
    openai.api_key = LLM_API_KEY
else:
    LLM_API_KEY = None

app = FastAPI()

# In-memory conversation state
conversations = {}
conv_lock = Lock()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("honeypot")


def parse_request_data(data):
    """
    Parse incoming JSON data into conversation_id and message text.
    Accepts multiple shapes of input data for robustness.
    """
    conversation_id = None
    text = ""
    if not isinstance(data, dict):
        return conversation_id, text
    # Try various keys for conversation ID
    if "conversation_id" in data:
        conversation_id = data.get("conversation_id")
    elif "sessionId" in data:
        conversation_id = data.get("sessionId")
    elif "conversation" in data and isinstance(data["conversation"], dict):
        conversation_id = data["conversation"].get("id")
        # If text inside conversation
        if "text" in data["conversation"]:
            text = data["conversation"].get("text", "")
    # Try to extract message text from other fields
    if not text:
        if "message" in data:
            msg_field = data["message"]
            if isinstance(msg_field, dict):
                text = msg_field.get("text", "")
            elif isinstance(msg_field, str):
                text = msg_field
        elif "text" in data:
            text = data.get("text", "")
    # Ensure text is a string
    return conversation_id, text or ""


def extract_intelligence(text):
    """
    Extract intelligence items from the message text.
    Returns a dictionary with lists of found items (deduplicated).
    """
    # Patterns for extraction
    upi_pattern = r'[\w\.-]{2,}@[a-zA-Z]{2,}'
    bank_pattern = r'\b\d{9,18}\b'
    ifsc_pattern = r'\b[A-Z]{4}0[A-Z0-9]{6}\b'
    url_pattern = r'https?://[^\s]+'
    card_pattern = r'\b\d{16}\b'
    otp_pattern = r'\b\d{4,6}\b'

    # Find all matches
    upis = re.findall(upi_pattern, text)
    banks = re.findall(bank_pattern, text)
    cards = re.findall(card_pattern, text)
    # Exclude 16-digit cards from bank accounts
    accounts = [acc for acc in banks if len(acc) != 16 or acc not in cards]
    otps = re.findall(otp_pattern, text)
    # Remove any OTPs that are 16 digits (shouldn't be)
    otps = [otp for otp in otps if not (len(otp) == 16)]
    ifscs = re.findall(ifsc_pattern, text, flags=re.IGNORECASE)
    # Normalize IFSC codes to uppercase
    ifscs = [code.upper() for code in ifscs]
    urls = re.findall(url_pattern, text)
    # Clean trailing punctuation from URLs
    phishing_urls = [url.rstrip('.,;:!') for url in urls]

    # Deduplicate all lists
    upis = list(dict.fromkeys(upis))
    accounts = list(dict.fromkeys(accounts))
    cards = list(dict.fromkeys(cards))
    otps = list(dict.fromkeys(otps))
    ifscs = list(dict.fromkeys(ifscs))
    phishing_urls = list(dict.fromkeys(phishing_urls))

    return {
        "upi_ids": upis,
        "bank_accounts": accounts,
        "ifsc_codes": ifscs,
        "phishing_urls": phishing_urls,
        "card_numbers": cards,
        "otp_codes": otps
    }


def is_scam_message(text):
    """
    Heuristic check if a message is likely a scam.
    Checks for presence of certain keywords or extracted items.
    """
    if not text:
        return False
    lower = text.lower()
    # Keywords often found in scam messages
    scam_keywords = [
        "urgent", "money", "bank", "ifsc", "upi", "verify", 
        "otp", "password", "blocked", "lottery", "prize", "reward",
        "transfer", "debit", "suspension", "suspend", "tax", "fine"
    ]
    for kw in scam_keywords:
        if kw in lower:
            return True
    # Also if any intelligence items found
    items = extract_intelligence(text)
    for key, values in items.items():
        if values:  # non-empty list
            return True
    return False


def get_agent_reply(text, scam_detected):
    """
    Generate a human-like reply. If LLM is configured, use it; otherwise use a template.
    """
    # Fallback template replies
    scam_templates = [
        "I'm a bit confused — can you explain what I should do next?",
        "This sounds important, could you give me more details?",
        "I think I need more information to help. Can you clarify what you need?",
        "Could you explain a bit more about why this is urgent?"
    ]
    non_scam_templates = [
        "Sure, how can I assist you further?",
        "Alright, I'm happy to help. What would you like to do?",
        "Okay, let me know if there's anything you need."
    ]

    # Try LLM for scam scenarios if API key is available
    if scam_detected and LLM_API_KEY and openai:
        try:
            messages = [
                {"role": "system", "content": "You are a helpful friend responding to a suspicious message to keep a conversation going."},
                {"role": "user", "content": f"The message I received is: \"{text}\". Please reply as a concerned person asking for clarification."}
            ]
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=messages,
                max_tokens=150,
                n=1,
                stop=None,
                temperature=0.7,
                timeout=2
            )
            reply = response.choices[0].message.content.strip()
            return reply
        except Exception as e:
            logger.warning(f"LLM call failed: {e}")
    # Fallback to template reply
    import random
    if scam_detected:
        return random.choice(scam_templates)
    else:
        return random.choice(non_scam_templates)


@app.get("/")
async def root_health():
    """
    Health check endpoint at root.
    """
    return {"status": "honeypot api is running"}


@app.get("/honeypot")
async def honeypot_health():
    """
    Health check endpoint for /honeypot.
    """
    return {"status": "honeypot api is running"}


@app.post("/honeypot")
async def honeypot_endpoint(request: Request):
    """
    Main honeypot endpoint.
    Expects JSON with scam message and returns detection and extracted info.
    """
    # Authenticate API key
    api_key = request.headers.get("x-api-key")
    if api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    # Parse JSON body safely
    try:
        data = await request.json()
    except Exception as e:
        logger.warning(f"Invalid JSON received: {e}")
        # Return harmless response to allow tester connectivity
        return JSONResponse(status_code=200, content={"detail": "Invalid JSON payload"})

    # Extract conversation ID and message text
    conv_id, text = parse_request_data(data)
    if not conv_id:
        conv_id = str(uuid.uuid4())  # generate unique ID if missing

    # Log request details
    logger.info(f"Headers: {dict(request.headers)}")
    client_host = request.client.host if request.client else "unknown"
    logger.info(f"Remote address: {client_host}")
    logger.info(f"Message (first 200 chars): {text[:200]}")

    # Update conversation turn count safely
    with conv_lock:
        turns = conversations.get(conv_id, 0) + 1
        conversations[conv_id] = turns

    # Detect scam and extract intelligence
    scam_flag = is_scam_message(text)
    extracted = extract_intelligence(text)

    # Generate agent reply
    agent_reply = get_agent_reply(text, scam_flag)

    # Build response
    response_content = {
        "scam_detected": scam_flag,
        "agent_reply": agent_reply,
        "turns": turns,
        "extracted_intelligence": extracted
    }
    return JSONResponse(content=response_content)
