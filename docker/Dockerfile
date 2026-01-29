FROM public.ecr.aws/lambda/python:3.12

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY src /app/src
ENV PYTHONPATH=/app/src

CMD ["python", "-m", "attestor.main"]
