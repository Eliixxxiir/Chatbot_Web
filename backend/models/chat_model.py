from pydantic import BaseModel, Field
from datetime import datetime
from typing import List, Optional

# --- Request Models ---
class ChatQuery(BaseModel):
    user_id: str = Field(..., description="Unique identifier for the user.")
    query_text: str = Field(..., min_length=1, description="The text query from the user.")
    language: str = Field("en", description="Language of the query (e.g., 'en', 'hi', 'hinglish').")

# --- Response Models ---
class ChatResponse(BaseModel):
    bot_response: str = Field(..., description="The chatbot's response text.")
    status: str = Field(..., description="Status of the query (e.g., 'answered', 'unanswered', 'error').")
    language: str = Field(..., description="Language of the bot's response.")
    query_id: Optional[str] = Field(None, description="Optional ID for the processed query.")
    similarity_score: Optional[float] = Field(None, description="Cosine similarity score if answered by NLP.")

# --- Logging Models ---
class LogEntry(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.now, description="Timestamp of the interaction.")
    user_id: str = Field(..., description="User ID associated with the interaction.")
    query_text: str = Field(..., description="The original query text from the user.")
    bot_response_text: str = Field(..., description="The bot's response text.")
    status: str = Field(..., description="Status of the interaction (e.g., 'answered', 'unanswered', 'error').")
    language: str = Field(..., description="Language of the interaction.")
    similarity_score: Optional[float] = Field(None, description="Similarity score of the match, if applicable.")

# --- Admin Models ---
class AdminUser(BaseModel):
    username: str
    hashed_password: str
    role: str 

class AdminLogin(BaseModel):
    username: str
    password: str