FROM golang:alpine AS builder
RUN apk update && \
    apk add --no-cache go alpine-sdk git make ca-certificates && \
    update-ca-certificates
WORKDIR /go/client
COPY . .
ENTRYPOINT go test -v
