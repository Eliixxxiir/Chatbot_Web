import express from "express";
import fetch from "node-fetch";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

// Chatbot endpoint
app.post("/api/chat", async (req, res) => {
  const { message } = req.body;

  try {
    // Send message to Python NLP backend
    const response = await fetch("http://localhost:5001/get_answer", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: message }),
    });

    const data = await response.json();

    if (data.answer === "ASK_ADMIN") {
      // Store in DB or send email to admin
      return res.json({ reply: "I can't answer this. The admin will get back to you." });
    }

    res.json({ reply: data.answer });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ reply: "Server error. Please try again." });
  }
});

app.listen(5000, () => {
  console.log("Server running on port 5000");
});
