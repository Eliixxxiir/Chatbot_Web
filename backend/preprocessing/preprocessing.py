import time
import re
from typing import List, Optional

# Initialize flags for optional dependencies
SPACY_AVAILABLE = False
TEXTBLOB_AVAILABLE = False
NLP = None

class TranscriptProcessor:
    # Common filler words to remove
    FILLER_WORDS = {"um", "uh", "like", "you know", "okay", "so", "actually", "basically", "literally"}

    @staticmethod
    def initialize_dependencies():
        """Initialize NLP dependencies with proper error handling"""
        global SPACY_AVAILABLE, TEXTBLOB_AVAILABLE, NLP
        
        # Initialize spaCy
        try:
            import spacy
            NLP = spacy.load("en_core_web_sm")
            SPACY_AVAILABLE = True
            print(" spaCy initialized successfully")
        except ImportError as e:
            print(f" Failed to import spaCy: {str(e)}")
        except OSError as e:
            print(f" Failed to load English model: {str(e)}")
            print("Try running: python -m spacy download en_core_web_sm")
        
        # Initialize TextBlob
        try:
            from textblob import TextBlob
            TEXTBLOB_AVAILABLE = True
            print(" TextBlob initialized successfully")
        except ImportError as e:
            print(f" Failed to import TextBlob: {str(e)}")

    @staticmethod
    def remove_filler_words(text: str) -> str:
        """Removes filler words from the transcript."""
        words = text.split()
        filtered_words = [word for word in words if word.lower() not in TranscriptProcessor.FILLER_WORDS]
        return " ".join(filtered_words)

    @staticmethod
    def correct_grammar(text: str) -> str:
        """Corrects grammar & spelling using TextBlob if available."""
        if TEXTBLOB_AVAILABLE:
            try:
                from textblob import TextBlob
                return str(TextBlob(text).correct())
            except Exception as e:
                print(f" Grammar correction failed: {str(e)}")
                return text
        return text

    @staticmethod
    def segment_sentences(text: str) -> str:
        """Ensures proper sentence segmentation."""
        if SPACY_AVAILABLE and NLP is not None:
            try:
                doc = NLP(text)
                sentences = [sent.text.strip() for sent in doc.sents]
                return " ".join(sentences)
            except Exception as e:
                print(f" spaCy processing failed: {str(e)}")
                return TranscriptProcessor._basic_segmentation(text)
        return TranscriptProcessor._basic_segmentation(text)

    @staticmethod
    def _basic_segmentation(text: str) -> str:
        """Basic fallback sentence segmentation."""
        sentences = [s.strip() for s in re.split('[.!?]+', text) if s.strip()]
        return '. '.join(sentences) + ('.' if sentences else '')

    @staticmethod
    def preprocess_transcript(transcript: str) -> str:
        """Applies NLP techniques to clean up the transcript and logs time taken."""
        start_time = time.time()
        
        print("\n🔹 Original Transcript:\n", transcript)
        
        # Step 1: Remove filler words
        t1 = time.time()
        transcript = TranscriptProcessor.remove_filler_words(transcript)
        print("\n Filler words removed in", round(time.time() - t1, 4), "seconds")

        # Step 2: Grammar correction
        t2 = time.time()
        transcript = TranscriptProcessor.correct_grammar(transcript)
        print(" Grammar corrected in", round(time.time() - t2, 4), "seconds")

        # Step 3: Sentence segmentation
        t3 = time.time()
        transcript = TranscriptProcessor.segment_sentences(transcript)
        print(" Sentence segmentation done in", round(time.time() - t3, 4), "seconds")

        total_time = round(time.time() - start_time, 4)
        print("\n⏳ Total Preprocessing Time:", total_time, "seconds")
        print("\n🔹 Cleaned Transcript:\n", transcript)
        
        return transcript

# Initialize dependencies when module is loaded
TranscriptProcessor.initialize_dependencies()

# Example usage
if __name__ == "__main__":
    raw_transcript = "Um so I was like you know actually uh going to the uh market and uh it was really cool so yeah."
    preprocessed_transcript = TranscriptProcessor.preprocess_transcript(raw_transcript)