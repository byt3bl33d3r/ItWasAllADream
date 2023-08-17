FROM python:3.8-slim

RUN apt-get update && \
    apt-get install --no-install-recommends -y git curl && \
    rm -rf /var/lib/apt/lists/*

COPY . .

RUN pip3 install poetry pyOpenSSL dsinternals && \
    poetry config virtualenvs.create false && \
    poetry install

ENTRYPOINT [ "itwasalladream" ]
