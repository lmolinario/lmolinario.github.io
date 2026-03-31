from __future__ import annotations

import stripe

from fastapi import APIRouter, Depends, HTTPException, Request, Query
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models.scan import Scan
from app.schemas.report import CheckoutCreateRequest, CheckoutCreateResponse
from app.services.report_service import (
    get_or_create_report,
    set_report_checkout_session,
    mark_report_paid,
    persist_report_payload,
)
from app.services.analytics_service import track_event


stripe.api_key = settings.stripe_secret_key

router = APIRouter(prefix="/api/billing", tags=["billing"])


@router.post("/cancel")
def track_checkout_cancel(
    scan_id: int = Query(...),
    db: Session = Depends(get_db),
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    track_event(db, scan.id, "checkout_canceled")
    return {"status": "ok"}


@router.post("/checkout", response_model=CheckoutCreateResponse)
def create_checkout(payload: CheckoutCreateRequest, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == payload.scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    report = get_or_create_report(db, scan.id)

    if report.is_paid:
        raise HTTPException(status_code=400, detail="Report already unlocked")

    track_event(db, scan.id, "report_unlock_clicked")

    session = stripe.checkout.Session.create(
        payment_method_types=["card"],
        mode="payment",
        line_items=[{
            "price_data": {
                "currency": "eur",
                "product_data": {
                    "name": f"Digital Risk Scanner Report - {scan.domain}"
                },
                "unit_amount": settings.stripe_report_price_eur_cents,
            },
            "quantity": 1,
        }],
        success_url=(
            f"{settings.app_base_url}/"
            f"?paid=1&scan_id={scan.id}&session_id={{CHECKOUT_SESSION_ID}}"
        ),
        cancel_url=f"{settings.app_base_url}/?canceled=1&scan_id={scan.id}",
        metadata={
            "scan_id": str(scan.id),
        },
        custom_text={
            "submit": {
                "message": "Test mode: use card 4242 4242 4242 4242 to simulate payment."
            }
        }
    )

    set_report_checkout_session(db, report, session.id)

    track_event(
        db,
        scan.id,
        "checkout_created",
        {"stripe_session_id": session.id},
    )

    return CheckoutCreateResponse(checkout_url=session.url)


@router.get("/confirm")
def confirm_checkout_session(
    scan_id: int = Query(...),
    session_id: str = Query(...),
    db: Session = Depends(get_db),
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    report = get_or_create_report(db, scan.id)

    # Già sbloccato
    if report.is_paid:
        persist_report_payload(db, report, scan)
        return {"status": "ok", "is_paid": True, "source": "already_unlocked"}

    # La sessione deve corrispondere a quella salvata
    if not report.stripe_session_id or report.stripe_session_id != session_id:
        raise HTTPException(status_code=400, detail="Checkout session mismatch")

    try:
        session = stripe.checkout.Session.retrieve(session_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Unable to verify checkout session: {exc}")

    payment_status = getattr(session, "payment_status", None)

    if payment_status != "paid":
        return {"status": "pending", "is_paid": False, "payment_status": payment_status}

    report = mark_report_paid(
        db=db,
        stripe_session_id=session_id,
        payment_status=payment_status,
    )

    if report:
        persist_report_payload(db, report, scan)

    if report:
        track_event(
            db,
            report.scan_id,
            "checkout_completed",
            {"source": "session_verification", "stripe_session_id": session_id},
        )

    return {"status": "ok", "is_paid": True, "source": "session_verification"}


@router.post("/webhook")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=sig_header,
            secret=settings.stripe_webhook_secret,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid webhook: {exc}")

    event_type = event["type"]
    event_object = event["data"]["object"]

    if event_type == "checkout.session.completed":
        payment_status = getattr(event_object, "payment_status", None)
        session_id = getattr(event_object, "id", None)

        if payment_status == "paid" and session_id:
            report = mark_report_paid(
                db=db,
                stripe_session_id=session_id,
                payment_status=payment_status,
            )

            if report:
                scan = db.query(Scan).filter(Scan.id == report.scan_id).first()
                if scan:
                    persist_report_payload(db, report, scan)

                track_event(
                    db,
                    report.scan_id,
                    "checkout_completed",
                    {"source": "webhook", "stripe_session_id": session_id},
                )

    return {"status": "ok"}