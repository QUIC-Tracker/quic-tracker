A test suite for QUIC
=====================

.. image:: https://godoc.org/github.com/QUIC-Tracker/quic-tracker?status.svg
    :target: https://godoc.org/github.com/QUIC-Tracker/quic-tracker
    :alt: Documentation status


The test suite comprises a minimal Go implementation of QUIC which is
currently draft-16 and TLS-1.3 compatible, as well as several
test scenarii built upon this implementation. The test suite outputs its
result as JSON files, which contains the result, the decrypted packets
exchanged, as well as a pcap file and exporter secrets.

Installation
------------

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


Docker
------

Docker builds exist on `Docker Hub`_.

::

    docker run --network="host" quictracker/quictracker /http_get -h
    docker run --network="host" quictracker/quictracker /scenario_runner -h
    docker run --network="host" quictracker/quictracker /test_suite -h

.. _Docker Hub: https://hub.docker.com/r/quictracker/quictracker/
