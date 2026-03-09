from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager
from pydantic import BaseModel
import joblib
import os
import numpy as np
import tldextract
from src.features import FeatureExtractor
from src.train import train_model

# Global variables for model and extractor
model = None
extractor = FeatureExtractor()

def load_model_file():
    global model
    model_path = "models/phishing_model.joblib"
    if os.path.exists(model_path):
        model = joblib.load(model_path)
        print("Model loaded successfully.")
        return True
    return False

@asynccontextmanager
async def lifespan(app: FastAPI):
    if not load_model_file():
        print("Model file not found. Starting automatic training...")
        try:
            train_model()
            if load_model_file():
                print("Model trained and loaded successfully.")
        except Exception as e:
            print(f"CRITICAL ERROR: Could not train model: {e}")
    yield

# Initialize App
app = FastAPI(
    title="Phishing Detection API",
    description="API to detect if a website is legitimate or phishing based on URL features.",
    version="1.0.0",
    lifespan=lifespan
)

# Define Input Schema
class UrlRequest(BaseModel):
    url: str

# Mount the static directory to serve CSS/JS if needed, or just the index.html
if not os.path.exists("src/static"):
    os.makedirs("src/static")
app.mount("/static", StaticFiles(directory="src/static"), name="static")

@app.get("/")
def read_root():
    # Serve the frontend UI
    return FileResponse('src/static/index.html')

@app.get("/health")
def health_check():
    return {"status": "online", "message": "Phishing Detection System API"}

@app.post("/reload")
def reload_model():
    if load_model_file():
        return {"status": "success", "message": "Model reloaded successfully"}
    raise HTTPException(status_code=503, detail="Model file not found. Please run train.py first.")

@app.post("/predict")
def predict_url(request: UrlRequest):
    url = request.url
    # 1. Auto-add protocol if missing (User friendly fix)
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    # 2. Domain Suffix Check (filters out inputs like 'http://dinesh' or random text)
    if not tldextract.extract(url).suffix:
        raise HTTPException(status_code=400, detail="Invalid Domain. URL must have a valid suffix (e.g. .com, .net)")

    if not model:
        raise HTTPException(status_code=503, detail="Model not loaded")

    try:
        # 1. Extract features from the input URL
        features = extractor.extract_features(url)
        
        # 2. Reshape for the model (1 sample, n features)
        features_array = np.array(features).reshape(1, -1)
        
        # 3. Predict
        prediction = model.predict(features_array)[0]
        probability = model.predict_proba(features_array)[0][prediction]

        result = "Phishing" if prediction == 1 else "Legitimate"

        return {
            "url": url,
            "prediction": result,
            "confidence": float(probability),
            "is_phishing": bool(prediction == 1)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
