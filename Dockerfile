FROM python:3-alpine

ENV PIP_NO_CACHE_DIR="true" \
    PYTHONPATH="/code"

WORKDIR /code

COPY code/pip-requirements.txt .
RUN pip install -r pip-requirements.txt && mkdir /logs

ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown
ARG SOURCE=https://github.com/mcbyute-it/fiberhome_exporter

LABEL Name=fiberhome_exporter \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.revision=$REVISION \
      org.opencontainers.image.source=$SOURCE \
      org.opencontainers.image.created=$CREATED

COPY code/ .

EXPOSE 6145

CMD ["python", "collector.py"]