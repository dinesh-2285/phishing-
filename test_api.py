from fastapi.testclient import TestClient
from src.app import app

client = TestClient(app)

def test_read_root():
    """Test the health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "online", "message": "Phishing Detection System API"}

def test_predict_structure():
    """
    Test the prediction endpoint. 
    Note: If the model is not trained, this returns 503, which we handle.
    """
    payload = {"url": "http://google.com"}
    response = client.post("/predict", json=payload)
    
    if response.status_code == 503:
        assert response.json()["detail"] == "Model not loaded"
    else:
        assert response.status_code == 200
        data = response.json()
        assert "prediction" in data
        assert "confidence" in data
        assert "is_phishing" in data

def test_predict_invalid_domain():
    """Test that invalid domains are rejected."""
    payload = {"url": "dinesh"}
    response = client.post("/predict", json=payload)
    assert response.status_code == 400
    assert "Invalid Domain" in response.json()["detail"]

def test_predict_auto_protocol():
    """Test that protocol is added automatically."""
    payload = {"url": "google.com"}
    response = client.post("/predict", json=payload)
    # Should be 200 (OK) or 503 (Model not loaded), but NOT 400
    assert response.status_code in [200, 503]

def test_reload_model():
    """Test the model reload endpoint."""
    response = client.post("/reload")
    
    if response.status_code == 503:
        assert "Model file not found" in response.json()["detail"]
    else:
        assert response.status_code == 200
        assert response.json() == {"status": "success", "message": "Model reloaded successfully"}