from typing import List
from numpy import dot
from numpy.linalg import norm
import logging

logger = logging.getLogger(__name__)

# Function to get the NLP model (will be loaded via model_loader.py)
from backend.nlp.model_loader import get_model

def get_embedding(text: str) -> List[float]:
    try:
        model = get_model()
        # Ensure the model is loaded before encoding
        if model is None:
            raise RuntimeError("NLP model is not loaded. Cannot generate embeddings.")
        embedding = model.encode(text, convert_to_tensor=False).tolist()
        return embedding
    except RuntimeError as e:
        logger.error(f"NLP model error during embedding generation: {e}")
        raise
    except Exception as e:
        logger.error(f"Error generating embedding for text '{text}': {e}", exc_info=True)
        raise

def cosine_similarity(vec1: List[float], vec2: List[float]) -> float:
    ''' Calculates the cosine similarity between two vectors.'''
    if not vec1 or not vec2:
        return 0.0 # Handle empty vectors gracefully
    
    # Convert lists to numpy arrays for efficient dot product and norm
    # (assuming numpy is installed as a dependency of sentence_transformers/scipy)
    try:
        import numpy as np
        vec1_np = np.array(vec1)
        vec2_np = np.array(vec2)
        
        # Calculate dot product
        dot_product = np.dot(vec1_np, vec2_np)
        
        # Calculate norms
        norm_vec1 = np.linalg.norm(vec1_np)
        norm_vec2 = np.linalg.norm(vec2_np)
        
        if norm_vec1 == 0 or norm_vec2 == 0:
            return 0.0 # Avoid division by zero
        
        return dot_product / (norm_vec1 * norm_vec2)
    except ImportError:
        logger.warning("Numpy not found for efficient cosine similarity. Falling back to manual calculation.")
        # Fallback to manual calculation if numpy is not available
        # This is less efficient but ensures functionality
        dot_product = sum(v1 * v2 for v1, v2 in zip(vec1, vec2))
        norm_vec1 = sum(v**2 for v in vec1)**0.5
        norm_vec2 = sum(v**2 for v in vec2)**0.5
        
        if norm_vec1 == 0 or norm_vec2 == 0:
            return 0.0
            
        return dot_product / (norm_vec1 * norm_vec2)
    except Exception as e:
        logger.error(f"Error calculating cosine similarity: {e}", exc_info=True)
        return 0.0