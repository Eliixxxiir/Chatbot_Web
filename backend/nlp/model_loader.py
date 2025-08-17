from sentence_transformers import SentenceTransformer
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Global model instance
model: Optional[SentenceTransformer] = None

def load_nlp_model(model_name: str) -> None:
    """
    Loads the sentence transformer model for generating embeddings.
    Args:
        model_name: Name of the model to load (e.g., 'paraphrase-multilingual-MiniLM-L12-v2')
    """
    global model
    try:
        logger.info(f"Loading NLP model: {model_name}")
        model = SentenceTransformer(model_name)
        logger.info("NLP model loaded successfully")
    except Exception as e:
        logger.error(f"Error loading NLP model: {e}", exc_info=True)
        raise

def get_model() -> Optional[SentenceTransformer]:
    """Returns the loaded model instance."""
    return model

def generate_embedding(text: str) -> list:
    """
    Generates embedding for the given text using the loaded model.
    Args:
        text: Input text to generate embedding for
    Returns:
        List of floats representing the text embedding
    """
    if not model:
        raise RuntimeError("NLP model not loaded")
    try:
        embedding = model.encode(text, convert_to_tensor=False)
        return embedding.tolist()
    except Exception as e:
        logger.error(f"Error generating embedding: {e}", exc_info=True)
        raise

# Load model on import or call explicitly once on app startup
load_nlp_model("paraphrase-multilingual-MiniLM-L12-v2")
