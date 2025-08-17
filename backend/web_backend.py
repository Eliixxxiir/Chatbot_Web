from fastapi import APIRouter

router = APIRouter()

@router.get("/")
async def home():
    return {"message": "Welcome to the web backend!"}

@router.get("/users/{user_id}")
async def get_user(user_id: int):
    return {"user_id": user_id, "message": "User data retrieved."}