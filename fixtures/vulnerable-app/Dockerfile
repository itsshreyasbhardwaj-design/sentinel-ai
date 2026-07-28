# Intentionally insecure fixture for Sentinel AI's test suite. Do not deploy.
FROM node:latest

ARG NPM_TOKEN=npm_aB3dEf9HiJkLmN0pQrStUvWxYz123456789012
ENV DATABASE_PASSWORD=SuperSecretProdPassword123

RUN curl -fsSL https://example.com/install.sh | sh

ADD https://example.com/binary.tar.gz /opt/

COPY . /app
WORKDIR /app

CMD ["node", "src/api.js"]
