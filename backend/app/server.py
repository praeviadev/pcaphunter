from pathlib import Path
import shutil
import tempfile

from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://134.199.206.236:3000",
        "http://localhost:3000",
        "https://pcaphunter.com",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/analyze")
async def analyze(pcap: UploadFile = File(...)):
    temp_dir = Path(tempfile.mkdtemp(prefix="pcaphunter_"))
    temp_path = temp_dir / pcap.filename

    with temp_path.open("wb") as f:
        shutil.copyfileobj(pcap.file, f)

    # Placeholder response so frontend works
    # Replace this with your real parsing/analyzer call
    return {
        "verdict": "LEGITIMATE",
        "findings": [],
        "raw_logs": {},
        "indicators": [],
        "uploaded_file": pcap.filename,
    }
