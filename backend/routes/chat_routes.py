from fastapi import APIRouter, HTTPException
from backend.models.chat_model import ChatQuery, ChatResponse, LogEntry
from backend.db.mongo_utils import get_mongo_db, insert_log_entry, get_all_faqs
from backend.nlp.similarity import get_embedding, cosine_similarity
import logging
from datetime import datetime
from typing import List
import os

logger = logging.getLogger(__name__)
router = APIRouter()

# Configuration
CONFIDENCE_THRESHOLD = 0.2  # similarity threshold to accept FAQ answer
KEYWORDS_COLLECTION = os.getenv("KEYWORDS_COLLECTION", "keywords")


async def get_synonyms_from_db(query_text: str, language: str) -> List[str]:
    """
    Retrieve synonyms from MongoDB to expand user query.
    """
    db = get_mongo_db()
    synonyms_collection = db[KEYWORDS_COLLECTION]

    query_words = [word.strip().lower() for word in query_text.split() if word.strip()]

    # Field depends on language
    search_field = "english_synonyms" if language == 'en' else "hindi_synonyms"

    synonym_docs = list(synonyms_collection.find({search_field: {"$in": query_words}}))

    expanded_keywords = []
    for doc in synonym_docs:
        expanded_keywords.append(doc.get('english_keyword', ''))
        expanded_keywords.append(doc.get('hindi_keyword', ''))
        expanded_keywords.extend(doc.get('english_synonyms', []))
        expanded_keywords.extend(doc.get('hindi_synonyms', []))

    # Remove duplicates and empty strings
    expanded_keywords = [kw for kw in set(expanded_keywords) if kw]

    return expanded_keywords


@router.post("/chat", response_model=ChatResponse)
async def chat_with_bot(query: ChatQuery):
    db = get_mongo_db()

    user_query_text = query.query_text
    user_id = query.user_id
    language = query.language

    logger.info(f"Received chat query from {user_id} ({language}): '{user_query_text}'")

    bot_response_text = ""
    status_text = "unanswered"
    similarity_score = None

    try:
        # 1. Expand query with synonyms
        synonym_keywords = await get_synonyms_from_db(user_query_text, language)
        logger.info(f"Synonyms for query '{user_query_text}': {synonym_keywords}")

        expanded_query_text = user_query_text + " " + " ".join(synonym_keywords)
        logger.info(f"Expanded query text for embedding: '{expanded_query_text}'")

        # 2. Generate embedding for expanded query
        user_embedding = get_embedding(expanded_query_text)

        # 3. Retrieve all FAQs
        all_faqs = get_all_faqs()
        if not all_faqs:
            logger.warning("No FAQs found in the database.")
            bot_response_text = "I'm sorry, my knowledge base is currently empty. Please try again later."
            status_text = "unanswered"

            await insert_log_entry(LogEntry(
                timestamp=datetime.now(),
                user_id=user_id,
                query_text=user_query_text,
                bot_response_text=bot_response_text,
                status=status_text,
                language=language
            ).dict())
            return ChatResponse(bot_response=bot_response_text, status=status_text, language=language)

        # 4. Find best matching FAQ by cosine similarity
        best_match_faq = None
        highest_similarity = -1.0

        for faq in all_faqs:
            faq_embedding = faq.get('embedding')
            if not faq_embedding:
                logger.warning(f"FAQ with ID {faq.get('question_id', 'N/A')} missing embedding. Skipping.")
                continue

            current_similarity = cosine_similarity(user_embedding, faq_embedding)
            logger.debug(f"FAQ ID {faq.get('question_id')} similarity: {current_similarity:.4f}")

            if current_similarity > highest_similarity:
                highest_similarity = current_similarity
                best_match_faq = faq

        similarity_score = highest_similarity
        faq_id = best_match_faq.get('question_id', 'N/A') if best_match_faq else 'None'
        logger.info(f"Highest similarity found: {highest_similarity:.4f} for FAQ ID: {faq_id}")

        # 5. Decide on answer based on threshold
        if best_match_faq and highest_similarity >= CONFIDENCE_THRESHOLD:
            if language == 'hi' and best_match_faq.get('answer_hi'):
                bot_response_text = best_match_faq.get('answer_hi', "Answer not available in Hindi.")
            elif best_match_faq.get('answer_en'):
                bot_response_text = best_match_faq.get('answer_en', "Answer not available in English.")
            else:
                bot_response_text = "I found a relevant answer, but it's not available in your selected language."
            status_text = "answered"
        else:
            bot_response_text = ("I'm sorry, I don't have a precise answer for that right now. "
                                 "Your query has been noted for review by our team.")
            status_text = "unanswered"
            # Send email to admin with full query log info
            try:
                from backend.services.email_service import send_email
                subject = "Unanswered Query Notification"
                body = (
                    f"A new unanswered query was received.\n\n"
                    f"User ID: {user_id}\n"
                    f"Query Text: {user_query_text}\n"
                    f"Language: {language}\n"
                    f"Timestamp: {datetime.now()}\n"
                    f"Similarity Score: {similarity_score}\n"
                )
                admin_email = os.getenv("ADMIN_EMAIL_RECEIVER", "kaaamgar.sahayak@gmail.com")
                send_email(subject, body, admin_email)
                logger.info(f"Unanswered query email sent to {admin_email}")
            except Exception as e:
                logger.error(f"Failed to send unanswered query email: {e}", exc_info=True)

    except Exception as e:
        logger.error(f"Error processing chat query '{user_query_text}': {e}", exc_info=True)
        bot_response_text = "An internal error occurred while processing your request. Please try again."
        status_text = "error"

        await insert_log_entry(LogEntry(
            timestamp=datetime.now(),
            user_id=user_id,
            query_text=user_query_text,
            bot_response_text=bot_response_text,
            status=status_text,
            language=language,
            similarity_score=similarity_score
        ).dict())
        raise HTTPException(status_code=500, detail="Internal server error.")

    # Log interaction (except when error already logged)
    if status_text != "error":
        await insert_log_entry(LogEntry(
            timestamp=datetime.now(),
            user_id=user_id,
            query_text=user_query_text,
            bot_response_text=bot_response_text,
            status=status_text,
            language=language,
            similarity_score=similarity_score
        ).dict())

    return ChatResponse(
        bot_response=bot_response_text,
        status=status_text,
        language=language,
        similarity_score=similarity_score
    )
