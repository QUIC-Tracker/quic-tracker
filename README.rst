A test suite for QUIC
=====================


The test suite comprises a minimal Go implementation of QUIC which is
currently draft-13 and TLS-1.3-draft-28 compatible, as well as several
test scenarii built upon this implementation. The test suite outputs its
result as JSON files, which contains the result, the decrypted packets
exchanged, as well as a pcap file and exporter secrets.

You should have Go 1.9, tcpdump, libpcap libraries and header installed
before starting.

::

    go get github.com/QUIC-Tracker/quic-tracker
    cd $GOPATH/src/github.com/mpiraux/pigotls
    make

The test suite is run by the scripts in ``bin/test_suite/``. For help
about their usage see:

::

    go run bin/test_suite/scenario_runner.go -h
    go run bin/test_suite/test_suite.go -h
