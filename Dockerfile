FROM python:3-alpine

LABEL Name=fiberhome_exporter

ENV PIP_NO_CACHE_DIR="true" \
    PYTHONPATH="/code"

WORKDIR /code

COPY code/pip-requirements.txt .
RUN pip install -r pip-requirements.txt && mkdir /logs

COPY code/ .

EXPOSE 6145

CMD ["python", "collector.py"]