FROM golang:1.19

WORKDIR /app

COPY . .

RUN go build -o api-gateway .

CMD ["./api-gateway"]
