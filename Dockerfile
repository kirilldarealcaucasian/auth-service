FROM golang:1.22.0

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

CMD go run main.go