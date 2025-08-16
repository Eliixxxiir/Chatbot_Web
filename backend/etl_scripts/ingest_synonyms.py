import pandas as pd
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
import os
import logging
from dotenv import load_dotenv
from typing import List, Dict, Any

# --- Configuration ---
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', '.env'))

MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME", "chatbot_db")
KEYWORDS_COLLECTION = os.getenv("KEYWORDS_COLLECTION", "keywords")
SYNONYMS_DATA_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'keywords_synonyms.csv')

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def run_synonyms_etl(data_path: str):
    """
    Runs the ETL pipeline to ingest synonyms data into MongoDB.
    This version handles the dual-lingual synonym CSV format.
    """
    logger.info("Starting synonyms ETL pipeline...")
    client = None
    try:
        # --- 1. Connect to MongoDB ---
        logger.info("Connecting to MongoDB for synonyms ETL...")
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        client.admin.command('ping')
        db = client[DB_NAME]
        keywords_collection = db[KEYWORDS_COLLECTION]
        logger.info("Connected to MongoDB for synonyms ETL.")

        # --- 2. Extract Data ---
        logger.info(f"Extracting synonyms data from {data_path}...")
        df = pd.read_csv(data_path, keep_default_na=False)
        logger.info(f"Extracted {len(df)} rows from CSV.")

        # --- 3. Transform Data & Clean ---
        synonym_docs = []
        for _, row in df.iterrows():
            english_keyword = str(row['english_keyword']).strip().lower()
            hindi_keyword = str(row['hindi_keyword']).strip().lower()
            english_synonyms = [s.strip().lower() for s in str(row['english_synonym']).split(',')]
            hindi_synonyms = [s.strip().lower() for s in str(row['hindi_synonym']).split(',')]
            
            if english_keyword and hindi_keyword:
                doc = {
                    "english_keyword": english_keyword,
                    "hindi_keyword": hindi_keyword,
                    "english_synonyms": english_synonyms,
                    "hindi_synonyms": hindi_synonyms
                }
                synonym_docs.append(doc)
        
        logger.info(f"Transformed {len(synonym_docs)} synonym entries.")

        # --- 4. Load Data ---
        if synonym_docs:
            keywords_collection.delete_many({})
            keywords_collection.insert_many(synonym_docs)
            logger.info(f"Successfully loaded {len(synonym_docs)} synonym entries into MongoDB.")
        else:
            logger.warning("No synonym entries to load.")

    except FileNotFoundError:
        logger.error(f"Synonyms data file not found at: {data_path}")
    except ConnectionFailure as e:
        logger.error(f"MongoDB connection failed during ETL: {e}")
    except Exception as e:
        logger.error(f"An error occurred during ETL: {e}", exc_info=True)
    finally:
        if client:
            client.close()
            logger.info("MongoDB connection closed for synonyms ETL.")

if __name__ == "__main__":
    if not os.path.exists(SYNONYMS_DATA_PATH):
        logger.error(f"Synonyms data file not found: {SYNONYMS_DATA_PATH}")
        logger.info("Please ensure 'keywords_synonyms.csv' is in the 'data/' directory at the project root.")
    else:
        run_synonyms_etl(SYNONYMS_DATA_PATH)