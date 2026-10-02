"""
Telegram webhook handler for inline button callbacks.
"""
import asyncio
import json
import logging
from fastapi import APIRouter, Request, HTTPException
from lattice.core.events import acknowledge_alert
from lattice.core.config import set_config_value, get_config_value
from lattice.notifications.telegram import handle_callback as process_callback

router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])
logger = logging.getLogger(__name__)

@router.post("/telegram")
async def telegram_webhook(request: Request):
    import hmac
    from lattice.core.config import load_config
    config = load_config()
    secret = config.master.telegram_secret
    if not secret:
        raise HTTPException(
            status_code=503,
            detail="Telegram webhook not configured. Run 'lattice telegram setup' on the master device to enable.",
        )
    else:
        provided = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
        if not hmac.compare_digest(provided.encode(), secret.encode()):
            raise HTTPException(status_code=403, detail="Invalid webhook secret")
    """Handle Telegram callback queries."""
    try:
        data = await request.json()
        logger.debug(f"Telegram webhook received: {data}")

        # Telegram sends callback data in a specific structure
        callback_query = data.get("callback_query")
        if not callback_query:
            raise HTTPException(status_code=400, detail="No callback_query")

        callback_data = callback_query.get("data")
        if not callback_data:
            raise HTTPException(status_code=400, detail="No data in callback")

        # Parse the JSON payload
        try:
            payload = json.loads(callback_data)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid callback data")

        # Telegram callback processing uses synchronous HTTP/retry
        # helpers. Keep that work off FastAPI's asyncio event loop.
        await asyncio.to_thread(
            process_callback,
            payload,
            callback_query,
        )

        return {"status": "ok"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Telegram webhook error: {e}")
        raise HTTPException(status_code=500, detail="Telegram webhook processing failed")
