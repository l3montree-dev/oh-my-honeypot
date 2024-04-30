FROM golang:1.22.2@sha256:72885e2245d6bcc63af0538043c63454878a22733587af87a4cfb12268d03baf as build-env

WORKDIR /go/src/app

HEALTHCHECK NONE

COPY . .

RUN go get -d -v ./...
RUN go build -o honeypot ./cmd/main.go

# checkov:skip=CKV_DOCKER_3
FROM gcr.io/distroless/base-debian12:nonroot@sha256:e238d402d6de8907263a79122ea6fb2238d336abf6b971de323bb72ef4001ee4

COPY --from=build-env /go/src/app/honeypot /go/src/app/honeypot
COPY --from=build-env /go/src/app/dbip-country.csv /go/src/app/dbip-country.csv
WORKDIR /go/src/app

CMD ["./honeypot"]

