FROM golang:1.25-alpine AS builder

RUN apk add --no-cache gcc musl-dev clang make libbpf-dev linux-headers

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o ndepa-scan ./cmd/ndepa-scan

FROM alpine:3.19

RUN apk add --no-cache ca-certificates libbpf elfutils-dev

WORKDIR /app
COPY --from=builder /app/ndepa-scan /usr/local/bin/ndepa-scan

ENTRYPOINT ["/usr/local/bin/ndepa-scan"]
CMD ["trace"]
