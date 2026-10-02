# Imagen de la API. Railway la construye y lee el puerto y la base desde variables.
FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o login ./cmd/login

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
WORKDIR /app
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
COPY --from=builder /app/login ./login
RUN chown appuser:appgroup ./login
USER appuser
EXPOSE 8080
CMD ["./login"]
