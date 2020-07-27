FROM golang:1.14-alpine
RUN apk add --no-cache make cmake gcc g++ git openssl openssl-dev perl-test-harness-utils tcpdump libpcap libpcap-dev libbsd-dev perl-scope-guard perl-test-tcp curl bash
RUN curl -o /usr/bin/wait-for-it https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh && chmod +x /usr/bin/wait-for-it
RUN mkdir -p /go/src/github.com/tiferrei/quic-tracker
ADD . /go/src/github.com/tiferrei/quic-tracker
WORKDIR /go/src/github.com/tiferrei/quic-tracker
ENV GOPATH /go
RUN go get -v ./... || true
WORKDIR /go/src/github.com/tiferrei/pigotls
RUN make
WORKDIR /go/src/github.com/mpiraux/ls-qpack-go
RUN make
WORKDIR /go/src/github.com/tiferrei/quic-tracker
RUN go build -o /run_adapter bin/run_adapter/main.go
ENTRYPOINT ["wait-for-it", "server:4433", "-s", "--", "/run_adapter"]
