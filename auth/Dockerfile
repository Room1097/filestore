FROM python:3.11-slim

WORKDIR /app

RUN pip install bcrypt

COPY auth_server.py .

EXPOSE 8000

ENTRYPOINT ["python", "auth_server.py"]
