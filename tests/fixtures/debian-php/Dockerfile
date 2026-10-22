FROM debian:12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends php8.2-cli=8.2.18-1~deb12u1 \
 && rm -rf /var/lib/apt/lists/*

CMD ["php", "-v"]
