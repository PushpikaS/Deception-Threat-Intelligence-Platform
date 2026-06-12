FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY shared/ ./shared/
COPY honeypot-api/ ./honeypot-api/
WORKDIR /build/shared
RUN go mod tidy
WORKDIR /build/honeypot-api
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /app /app
EXPOSE 8081
CMD ["/app"]
