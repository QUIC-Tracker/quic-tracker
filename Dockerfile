FROM golang:1.11-alpine
RUN apk add --no-cache make cmake gcc g++ git openssl openssl-dev perl-test-harness-utils tcpdump libpcap libpcap-dev libbsd-dev perl-scope-guard perl-test-tcp python3 yarn && \
    pip3 install --upgrade git+https://github.com/QUIC-Tracker/dissector git+https://github.com/QUIC-Tracker/web-app

RUN echo "from quic_tracker.app import app as application" > /web-app.wsgi
RUN ln -s /usr/lib/python3.7/site-packages/quic_tracker/traces /traces
WORKDIR /usr/lib/python3.7/site-packages/quic_tracker/static
RUN yarn install
EXPOSE 5000
ENV QUIC_TRACKER_ALLOW_UPLOAD 1
ENV FLASK_APP=quic_tracker.app

RUN mkdir -p /go/src/github.com/QUIC-Tracker/quic-tracker
ADD . /go/src/github.com/QUIC-Tracker/quic-tracker 
WORKDIR /go/src/github.com/QUIC-Tracker/quic-tracker
ENV GOPATH /go
RUN go get -v || true
WORKDIR /go/src/github.com/mpiraux/pigotls
RUN make
WORKDIR /go/src/github.com/mpiraux/ls-qpack-go
RUN make
WORKDIR /go/src/github.com/QUIC-Tracker/quic-tracker
RUN go build -o /test_suite bin/test_suite/test_suite.go && \
    go build -o /scenario_runner bin/test_suite/scenario_runner.go && \
    go build -o /http_get bin/http/http_get.go
CMD ["/test_suite"]
