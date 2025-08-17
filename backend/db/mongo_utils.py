import logging
from typing import List, Dict, Any, Optional
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
import bcrypt

logger = logging.getLogger(__name__)

# Clients and DBs
client: Optional[MongoClient] = None
chatbot_db = None
admin_db = None

async def connect_to_mongo(mongo_uri: str, chatbot_db_name: str, admin_db_name: str):
    global client, chatbot_db, admin_db
    try:
        client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
        client.admin.command('ping')
        chatbot_db = client[chatbot_db_name]
        admin_db = client[admin_db_name]
        logger.info(f"✅ Connected to MongoDB: {chatbot_db_name} & {admin_db_name}")
    except ConnectionFailure as e:
        logger.error(f"❌ MongoDB connection failed: {e}")
        raise
    except Exception as e:
        logger.error(f"❌ Unexpected error connecting to MongoDB: {e}", exc_info=True)
        raise

async def close_mongo_connection():
    global client
    if client:
        client.close()
        logger.info("🔌 MongoDB connection closed.")

# ----- Chatbot DB Functions -----
def get_chatbot_db():
    if chatbot_db is None:
        raise ConnectionFailure("Chatbot DB connection not established.")
    return chatbot_db

def get_all_faqs() -> List[Dict[str, Any]]:
    faqs = list(get_chatbot_db()["faqs"].find({}, {"_id": 0}))
    logger.info(f"Fetched {len(faqs)} FAQs from Chatbot DB.")
    return faqs
# Compatibility alias for old code
def get_mongo_db():
    return get_chatbot_db()

async def insert_log_entry(entry: Dict[str, Any]) -> str:
    result = get_chatbot_db()["logs"].insert_one(entry)
    logger.info(f"📝 Log entry inserted with ID: {result.inserted_id}")
    return str(result.inserted_id)

def get_unanswered_logs() -> List[Dict[str, Any]]:
    logs = get_chatbot_db()["logs"].find({
        "$or": [
            {"answer": None},
            {"answer": ""},
            {"answer": {"$exists": False}}
        ]
    })
    return [{**log, "_id": str(log["_id"])} for log in logs]

def get_all_logs_entries() -> List[Dict[str, Any]]:
    logs = get_chatbot_db()["logs"].find({})
    return [{**log, "_id": str(log["_id"])} for log in logs]


# ----- Admin DB Functions -----
def get_admin_db():
    if admin_db is None:
        raise ConnectionFailure("Admin DB connection not established.")
    return admin_db

# --- New: Insert into admin_marking ---
def insert_admin_marking(entry: Dict[str, Any]) -> str:
    result = get_admin_db()["admin_marking"].insert_one(entry)
    logger.info(f"Admin marking inserted with ID: {result.inserted_id}")
    return str(result.inserted_id)

# --- New: Insert into admin_answers ---
def insert_admin_answer(entry: Dict[str, Any]) -> str:
    result = get_admin_db()["admin_answers"].insert_one(entry)
    logger.info(f"Admin answer inserted with ID: {result.inserted_id}")
    return str(result.inserted_id)

async def create_user(user_data: Dict[str, Any]) -> str:
    users_collection = get_admin_db()["users"]

    if users_collection.find_one({"email": user_data["email"]}):
        raise ValueError("Email already registered")

    hashed_pw = bcrypt.hashpw(user_data["hashed_password"].encode('utf-8'), bcrypt.gensalt())
    user_data["hashed_password"] = hashed_pw.decode('utf-8')

    result = users_collection.insert_one(user_data)
    logger.info(f"👤 User registered with ID: {result.inserted_id}")
    return str(result.inserted_id)

async def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    return get_admin_db()["users"].find_one({"email": email})

async def verify_user(email: str, password: str) -> bool:
    user = await get_user_by_email(email)
    if not user:
        return False
    return bcrypt.checkpw(password.encode('utf-8'), user["hashed_password"].encode('utf-8'))

async def get_admin_user(email: str) -> Optional[Dict[str, Any]]:
    return get_admin_db()["admins"].find_one({"email": email})

async def create_admin_user(admin_data: Dict[str, Any]) -> str:
    result = get_admin_db()["admins"].insert_one(admin_data)
    return str(result.inserted_id)
