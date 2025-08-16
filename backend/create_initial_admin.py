# create_initial_admin_bcrypt.py
import pymongo
from pymongo import MongoClient
from passlib.context import CryptContext

# --- MongoDB connection ---
MONGO_URI = "mongodb+srv://Elixir:elixir@clutter.3ary0d9.mongodb.net/chatbot_db?retryWrites=true&w=majority"
client = MongoClient(MONGO_URI)

# --- Choose the correct DB and collection ---
admin_db = client["admin_db"]
admins_collection = admin_db["admins"]

# --- Password hashing ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

sample_admins = [
    {"email": "admin@example.com", "password": "Admin@123"},
    {"email": "kamgaradmin1@example.com", "password": "Kamgar@123"},
    {"email": "labouradmin2@example.com", "password": "Labour@123"},
]

# --- Hash the password using bcrypt ---
for admin in sample_admins:
    admin["hashed_password"] = pwd_context.hash(admin["password"])

# --- Insert admin if not exists ---
for admin in sample_admins:
    if admins_collection.find_one({"email": admin["email"]}):
        print(f"Admin with email {admin['email']} already exists.")
    else:
        admins_collection.insert_one({
            "email": admin["email"],
            "hashed_password": admin["hashed_password"],
            "role": "admin"  # must match login code field
        })
    print(f"Admin {admin['email']} added successfully to admin_db.admins.")
