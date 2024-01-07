FROM python:3.12.1-alpine

LABEL Name=fiberhome_exporter
EXPOSE 6145
ENV PIP_NO_CACHE_DIR="true"

ADD code /code
RUN pip install -r /code/pip-requirements.txt

WORKDIR /code
ENV PYTHONPATH '/code/'

CMD ["python" , "/code/collector.py"]