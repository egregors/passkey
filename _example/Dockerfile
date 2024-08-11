FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY . .

RUN go mod init passkey_demo && go mod tidy

RUN go build -o main ./*.go

FROM scratch

COPY --from=builder /app/main /main
COPY --from=builder /app/web /web

EXPOSE 8080

CMD ["/main"]