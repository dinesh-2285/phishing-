FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all project files (src, data, models if they exist)
COPY . .

# Expose the port (mainly for documentation, cloud providers ignore this)
EXPOSE 8000

# Start the API using the PORT environment variable (defaulting to 8000)
# This is crucial for platforms like Heroku/Render/Railway
CMD sh -c "uvicorn src.app:app --host 0.0.0.0 --port ${PORT:-8000}"