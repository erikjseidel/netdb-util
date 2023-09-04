FROM python:3.9
WORKDIR /netdb-util/app
COPY ./requirements.txt /netdb-util/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /netdb-util/requirements.txt
COPY ./app /netdb-util/app
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"]
