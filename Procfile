web: uvicorn src.app:app --host 0.0.0.0 --port $PORT
web: gunicorn -w 4 -k uvicorn.workers.UvicornWorker src.app:app --bind 0.0.0.0:$PORT