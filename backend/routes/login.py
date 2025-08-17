from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr
from backend.db.mongo_utils import get_user_by_email


import bcrypt

router = APIRouter()

class LoginData(BaseModel):
    email: EmailStr
    password: str

@router.post("/login")
async def login_user(data: LoginData):
    user = await get_user_by_email(data.email)
    if not user:
        raise HTTPException(status_code=400, detail="User not found")
    
    if not bcrypt.checkpw(data.password.encode('utf-8'), user["password"].encode('utf-8')):
        raise HTTPException(status_code=401, detail="Invalid password")
    
    # For now, return a fake token
    return {"message": "Login successful", "token": "dummy-token", "user": {"name": user["name"], "email": user["email"]}}
