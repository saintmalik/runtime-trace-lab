# ======================
# Build Stage
# ======================
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache \
    gcc \
    g++ \
    musl-dev \
    git \
    ca-certificates \
    && rm -rf /var/cache/apk/*

WORKDIR /build

COPY go.mod go.sum* ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o main .

# ======================
# Runtime Stage
# ======================
FROM alpine:3.20

RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    && rm -rf /var/cache/apk/*

RUN adduser -D -h /app appuser
WORKDIR /app

COPY --from=builder /build/main .

ENV PORT=8080 \
    APP_ENV=production \
    TZ=UTC \
    USER=appuser

USER appuser
EXPOSE 8080
CMD ["./main"]
