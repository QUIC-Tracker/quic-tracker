FROM golang:1.14-alpine
RUN apk add --no-cache make cmake gcc g++ git openssl openssl-dev perl-test-harness-utils tcpdump libpcap libpcap-dev libbsd-dev perl-scope-guard perl-test-tcp
RUN mkdir -p /go/src/github.com/tiferrei/quic-tracker
ADD . /go/src/github.com/tiferrei/quic-tracker
WORKDIR /go/src/github.com/tiferrei/quic-tracker
ENV GOPATH /go
RUN go get -v || true
WORKDIR /go/src/github.com/mpiraux/pigotls
RUN make
WORKDIR /go/src/github.com/mpiraux/ls-qpack-go
RUN make
WORKDIR /go/src/github.com/tiferrei/quic-tracker
RUN go build -o /run_adapter bin/run_adapter/main.go
CMD ["/run_adapter"]
