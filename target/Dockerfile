FROM python:3.12-slim
WORKDIR /app
COPY serve.py .
ENV PYTHONUNBUFFERED=1
EXPOSE 22 80
CMD ["python3", "serve.py"]
