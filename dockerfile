# Build stage
FROM golang:1.25.5-alpine AS builder
WORKDIR /app

# Install git for module download if needed
RUN apk add --no-cache git ca-certificates

# Copy go.mod and go.sum if present to leverage layer caching
COPY go.mod ./

# Copy the source
COPY . ./

# Build the binary
RUN go build -trimpath -ldflags="-s -w" -o /server .

# Final stage: small image
FROM alpine:3.19
RUN apk add --no-cache ca-certificates
WORKDIR /
COPY --from=builder /server /server

EXPOSE 1307
ENTRYPOINT ["/server"]
