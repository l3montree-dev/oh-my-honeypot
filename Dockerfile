FROM golang:1.20 as build-env

WORKDIR /go/src/app

COPY . .

RUN go get -d -v ./...
RUN go build -o honeypot ./cmd/main.go

FROM gcr.io/distroless/base

COPY --from=build-env /go/src/app/honeypot /go/src/app/honeypot
COPY --from=build-env /go/src/app/dbip-country.csv /go/src/app/dbip-country.csv
WORKDIR /go/src/app

CMD ["./honeypot"]

