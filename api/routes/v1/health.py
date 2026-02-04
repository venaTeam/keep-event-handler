from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()

@router.get("/health")
def health_check():
    return JSONResponse(
        content={"status": "ok"},
        status_code=200,
    )

@router.get("/")
def get_status():
    return JSONResponse(
        content="Event Handler Service Running\n",
        status_code=200,
        headers={"Content-Type": "text/plain"},
    )
