# apk_router.py

from fastapi import APIRouter
from fastapi.responses import FileResponse
import os

router = APIRouter()

APK_DIRECTORY = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "apk"))

@router.get("/download")
async def download_apk():
    apk_name = "app-release.apk"
    file_path = os.path.join(APK_DIRECTORY, apk_name)
    # Check 
    if os.path.exists(file_path):
        return FileResponse(
            path=file_path,
            media_type="application/vnd.android.package-archive",
            filename=apk_name
        )
    else:
        return {"error": f"APK not found at {file_path}"}