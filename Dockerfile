FROM golang:alpine AS builder

# Install git & make
# Git is required for fetching the dependencies
RUN apk update && \
    apk add --no-cache go git make ca-certificates && \
    update-ca-certificates

# Set the working directory for the container
WORKDIR /go/client

# Build the binary
COPY . .
FROM alpine
RUN apk update && \
    apk add --no-cache go ca-certificates tzdata && \
    update-ca-certificates

ENTRYPOINT go test -v
