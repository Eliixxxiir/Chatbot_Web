from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import difflib

app = Flask(__name__)
CORS(app)  # Allow requests from any origin (React frontend)

# Load dataset
df = pd.read_excel("data/labour_data.xlsx")

def search_dataset(query):
    questions = df['Question'].astype(str).tolist()
    answers = df['Answer'].astype(str).tolist()

    matches = difflib.get_close_matches(query, questions, n=1, cutoff=0.0)  # no cutoff, get best match always
    if matches:
        best_match = matches[0]
        idx = questions.index(best_match)
        answer = answers[idx]
        similarity = difflib.SequenceMatcher(None, query, best_match).ratio()
        return answer, similarity
    else:
        return None, 0.0

@app.route("/chat_api/chat", methods=["POST"])
def get_answer():
    data = request.get_json()
    query = data.get("query_text", "")
    answer, similarity = search_dataset(query)

    if answer is None:
        # No match found at all - fallback
        return jsonify({
            "bot_response": "ASK_ADMIN",
            "similarity_score": similarity
        })
    else:
        # Return best matched answer with similarity score
        return jsonify({
            "bot_response": answer,
            "similarity_score": similarity
        })

if __name__ == "__main__":
    app.run(port=5001, debug=True)
