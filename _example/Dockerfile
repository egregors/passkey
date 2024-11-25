# Description: Dockerfile for building the example application
# It should be call from the root directory of the project because of the context
FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY . .

RUN go build -o ./_example/main ./_example/*.go

FROM scratch

COPY --from=builder /app/_example/main /main
COPY --from=builder /app/_example/web /web

EXPOSE 8080

CMD ["/main"]