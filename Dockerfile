FROM python:3.11-slim

WORKDIR /app

# Copy application files
COPY . /app

# Expose web server port
EXPOSE 8080

ENV PYTHONUNBUFFERED=1
ENV PORT=8080

CMD ["python", "web_server.py"]
