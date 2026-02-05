# README.md
# Agentic Honey-Pot API

This FastAPI application implements the **Agentic Honey-Pot** for scam detection and intelligence extraction. It exposes a single `/honeypot` endpoint that accepts scam messages, detects scam content, responds with a human-like reply, and extracts items like UPI IDs, bank accounts, IFSC codes, phishing URLs, card numbers, and OTP codes.

## Requirements

- Python 3.11.x
- Set environment variable `API_KEY` (default is `my-secret-key-123`).
- Optionally set `OPENAI_API_KEY` (or `LLM_API_KEY`) for using an LLM for replies.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate      # on Windows use `.venv\\Scripts\\activate`
pip install -r requirements.txt
