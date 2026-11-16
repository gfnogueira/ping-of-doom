FROM python:3.13-alpine
RUN apk add --no-cache tcpdump
WORKDIR /app
COPY pod ./pod
