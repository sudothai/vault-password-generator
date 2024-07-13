FROM golang:1.20-alpine

WORKDIR /app

COPY . .

# Copy the config file into the image
COPY config.yaml .

RUN go build -o main .

CMD ["./main"]
