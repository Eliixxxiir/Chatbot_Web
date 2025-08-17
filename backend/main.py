

# --- Imports ---
import os
import logging
import jwt
from datetime import datetime, timedelta
from typing import Optional
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from jwt import exceptions as jwt_exceptions
from contextlib import asynccontextmanager
from fastapi.security import OAuth2PasswordBearer

# --- Routers ---
from backend.routes import chat_routes, admin_routes, register_routes, otp_routes
from backend.apk_router import router as apk_router
from backend.db.mongo_utils import connect_to_mongo, close_mongo_connection, get_admin_user
from backend.nlp.model_loader import load_nlp_model

# --- Load Environment Variables ---
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://Elixir:elixir@clutter.3ary0d9.mongodb.net/chatbot_db?retryWrites=true&w=majority")
DB_NAME = os.getenv("DB_NAME", "chatbot_db")
NLP_MODEL_NAME = os.getenv("NLP_MODEL_NAME", "paraphrase-multilingual-MiniLM-L12-v2")
ADMIN_DB_NAME = os.getenv("ADMIN_DB_NAME", "admin_db")
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-super-secret-key-please-change-this-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# --- Logging ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# --- Security ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/admin_api/token")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_admin_user(token: str = Depends(oauth2_scheme)) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        user = await get_admin_user(username)
        if user is None:
            raise credentials_exception
        return user
    except jwt_exceptions.PyJWTError:
        raise credentials_exception

# --- Lifespan Context Manager ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- Startup Logic ---
    try:
        logger.info("Starting backend services...")
        await connect_to_mongo(MONGO_URI, DB_NAME, ADMIN_DB_NAME)
        logger.info("MongoDB connected.")
        load_nlp_model(NLP_MODEL_NAME)
        logger.info("NLP model loaded.")
    except Exception as e:
        logger.error(f"Startup failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Backend failed to start")

    yield

    # --- Shutdown Logic ---
    logger.info("Shutting down backend...")
    await close_mongo_connection()
    logger.info("MongoDB connection closed.")

# --- FastAPI App ---
app = FastAPI(
    title="Shramik Saathi Chatbot Backend",
    description="Backend API for the multilingual chatbot assisting laborers in MP, India",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# --- CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for development/debugging
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# --- Routers ---
app.include_router(chat_routes.router, prefix="/chat_api", tags=["Chatbot"])
app.include_router(admin_routes.router, prefix="/admin_api", tags=["Admin"])
app.include_router(register_routes.router, prefix="/register_api", tags=["Register"])
app.include_router(otp_routes.router, prefix="/otp_api", tags=["OTP"])
app.include_router(apk_router, prefix="/app", tags=["APK Download"])

# --- Root ---
@app.get("/")
async def read_root():
    return {"message": "Shramik Saathi Chatbot Backend is running!"}