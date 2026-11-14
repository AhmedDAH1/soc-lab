# The lab's live console: a small web page that shows each step of the
# pipeline as it happens. Python standard library only, on the same base
# image as the target, so it adds nothing to download.
FROM python:3.12-slim
WORKDIR /console
COPY server.py .
COPY static ./static
ENV PYTHONUNBUFFERED=1
EXPOSE 8080
CMD ["python3", "server.py"]
