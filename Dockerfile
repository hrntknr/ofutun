FROM docker.io/library/golang:alpine as builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY ./ /app
RUN go build -o bin/main cmd/main.go

FROM docker.io/library/alpine:latest

COPY --from=builder /app/bin/main /usr/local/bin/ofutun

ENTRYPOINT [ "/usr/local/bin/ofutun" ]
