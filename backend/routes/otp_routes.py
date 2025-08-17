from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from backend.services import otp_service

router = APIRouter()

class PhoneNumber(BaseModel):
    phone: str

class OTPVerify(BaseModel):
    phone: str
    otp: str

@router.post("/send-otp")
def send_otp(data: PhoneNumber):
    phone = data.phone.strip()
    if len(phone) != 10 or not phone.isdigit():
        raise HTTPException(status_code=400, detail="Invalid phone number")

    otp = otp_service.generate_otp(phone)
    otp_service.send_otp_via_sms(phone, otp)
    return {"success": True, "message": "OTP sent successfully"}

@router.post("/verify-otp")
def verify_otp(data: OTPVerify):
    if otp_service.verify_otp(data.phone, data.otp):
        return {"success": True, "message": "OTP verified"}
    else:
        raise HTTPException(status_code=400, detail="Invalid OTP")
