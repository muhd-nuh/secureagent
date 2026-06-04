FROM python:3.11-slim

WORKDIR /app

# Only Flask needed, SQLite is built into Python
RUN pip install flask

COPY vulnerable_app.py .

CMD ["python", "vulnerable_app.py"]