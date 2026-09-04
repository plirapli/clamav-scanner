from datetime import datetime

from bson import ObjectId
from fastapi import APIRouter, HTTPException, Query

from core.mongo import get_scan_logs
from schemas.response import ApiResponse, ErrorResponse
from services.analysis import AnalysisService

router = APIRouter(prefix="/analysis", tags=["analysis"])
analysis_service = AnalysisService()


def _to_object_id(log_id: str) -> ObjectId:
    try:
        return ObjectId(log_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="invalid log id") from exc


def _serialize(doc: dict) -> dict:
    for key, value in list(doc.items()):
        if isinstance(value, datetime):
            doc[key] = value.isoformat()
        elif isinstance(value, ObjectId):
            doc[key] = str(value)
    return doc


@router.get("/scan-logs", response_model=ApiResponse)
async def list_scan_logs(
    virus_name: str | None = Query(None),
    application: str | None = Query(None),
    limit: int = Query(20, ge=1, le=100),
    skip: int = Query(0, ge=0),
):
    collection = get_scan_logs()
    query: dict = {"status": "infected"}
    if virus_name:
        query["virus_name"] = {"$regex": virus_name, "$options": "i"}
    if application:
        query["application"] = application

    cursor = collection.find(query).sort("created_at", -1).skip(skip).limit(limit)
    logs = [_serialize(doc) for doc in cursor]
    return ApiResponse(data={"total": len(logs), "items": logs})


@router.post(
    "/scan-logs/{log_id}/analyze",
    response_model=ApiResponse,
    responses={500: {"model": ErrorResponse}},
)
async def analyze_log(log_id: str):
    collection = get_scan_logs()
    doc = collection.find_one({"_id": _to_object_id(log_id)})
    if doc is None:
        raise HTTPException(status_code=404, detail="scan log not found")

    try:
        result = await analysis_service.analyze_log(_serialize(doc))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {exc}") from exc

    return ApiResponse(message="analysis completed", data=result)


@router.post(
    "/scan-logs/summary",
    response_model=ApiResponse,
    responses={500: {"model": ErrorResponse}},
)
async def summarize_logs(limit: int = Query(20, ge=1, le=100)):
    collection = get_scan_logs()
    cursor = collection.find({"status": "infected"}).sort("created_at", -1).limit(limit)
    logs = [_serialize(doc) for doc in cursor]
    if not logs:
        raise HTTPException(status_code=404, detail="no infected scan logs found")

    try:
        result = await analysis_service.summarize(logs)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {exc}") from exc

    return ApiResponse(message="summary completed", data=result)
