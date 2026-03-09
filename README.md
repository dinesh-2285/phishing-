# Phishing Website Detection System

A machine learning-based API to detect phishing URLs, built with FastAPI, Scikit-Learn, and Docker.

## Project Structure

- `src/`: Source code for API and Feature Extraction.
- `models/`: Stores the trained serialized model.
- `data/`: Place your `phishing_dataset.csv` here.
- `tests/`: Automated tests.

## Prerequisites

- Python 3.8+ installed.
- [Git](https://git-scm.com/) installed and added to PATH.

## How to Run
first setup an environment using terminal in your project folder
```bash
.\venv\Scripts\activate
```
### 1. Install Dependencies
Open your terminal in the project folder and run:

```bash
pip install -r requirements.txt
```

### 2. Train the Model
```bash
python src/train.py
```

### 3. Start the API
```bash
uvicorn src.app:app --reload
```

## How to Run (With Docker)

### 1. Start the API
Use the modern Docker Compose command:

```bash
docker compose up --build
```

The API will be available at: http://localhost:8000
API Documentation (Swagger UI): http://localhost:8000/docs

### 2. Train the Model
If you haven't trained the model yet, the API will return a 503 error. You can train it inside the running container environment:

```bash
# Run the training script using the api service defined in docker-compose
docker compose run --rm api python src/train.py
```

*Note: After training, you may need to restart the API container for it to load the new model.*

### 3. Run Tests

```bash
docker compose run --rm api pytest
```
