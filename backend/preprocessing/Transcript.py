import whisper
import torch
import os
import subprocess

# Check if ffmpeg is installed
subprocess.run(["ffmpeg", "-version"], check=True)

# Check if the audio file exists
audio_file_path = "D:/Data_Drive/Codes/Test/Monologue.webm"
print(f"Checking if audio file exists: {audio_file_path}")
assert os.path.exists(audio_file_path), f"Audio file not found at {audio_file_path}"

# Check if CUDA is available
print("Checking device availability...")
device = "cuda" if torch.cuda.is_available() else "cpu"
print(f"Device: {device}")

# Load the Whisper model
print("Loading Whisper model...")
model = whisper.load_model("small", device=device)
print("Model loaded successfully!")

# Transcribe the audio file
print("Starting transcription...")
result = model.transcribe(audio_file_path)
print("Transcription result (full dictionary):", result)

# Print only the plain transcript
print("\n--- Plain Transcript ---")
print(result["text"])

print("Script finished successfully!")
