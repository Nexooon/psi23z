FROM python:3.11

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir -r /app/requirements.txt

ENTRYPOINT ["python", "sensory_device.py"]
