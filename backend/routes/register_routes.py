from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr
from typing import Optional
from backend.db.mongo_utils import create_user  # fixed import

router = APIRouter()

class UserRegisterData(BaseModel):
    name: str
    email: EmailStr
    password: str
    address: Optional[str] = None
    workType: Optional[str] = None

@router.post("/register-user")
async def register_user(data: UserRegisterData):
    try:
        user_id = await create_user(data.dict())
        return {"message": "User registered successfully!", "user_id": user_id}
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal Server Error")
