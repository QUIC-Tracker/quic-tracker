# A test suite for QUIC

This work is part of my master thesis for my master's degree in Computer Science at [Université catholique de Louvain](https://uclouvain.be). It is supervised by Pr. Olivier Bonaventure and Quentin De Coninck.

It is two-fold:

- It is a test suite that exchanges packets with IETF-QUIC implementations to verify whether an implementation conforms with the IETF specification of QUIC. The test suite is consisting of several test scenarii. Each of them aims at testing a particular feature of the QUIC protocol. The test suite runs daily, and its results are available on [https://quic-tracker.info.ucl.ac.be](https://quic-tracker.info.ucl.ac.be). This is the main focus of my effort.

- It also contains a tool that collects HTTP Alt-Svc headers sent by web-servers of popular domain names in the hope of discovering IETF-QUIC capable hosts. It lists the versions advertised by the hosts, if any.

## Installation

### Test suite

The test suite comprises a minimal Go implementation of QUIC which is currently draft-11 and TLS-1.3-draft-28 compatible, as well as several test scenarii built upon this implementation. The test suite outputs its result as JSON files, which contains the result, the decrypted packets exchanged, as well as a pcap file and exporter secrets.

You should have Go 1.9, tcpdump, libpcap libraries and header installed before starting.

```
go get github.com/mpiraux/master-thesis
cd $GOPATH/github.com/mpiraux/pigotls
make
```


The test suite is run by `bin/scenario/scenario_runner.go`, e.g.:
```
go run bin/scenario/scenario_runner.go ietf_quic_hosts.txt [particular_scenario]
```

It takes as first parameter a tab-delimited CSV containing a list of hosts and particular URLs which will generate data when requested.

A second optional parameter exists to specify a particular scenario from the directory `scenarii` to run exclusively, e.g. `stream_opening_reordering`.

The results are printed to stdout.

### Web application

The web application is a Python Flask application that presents the test results in an human-readable way.

It is known to be working with Python 3.6, but it should be compatible with earlier Python 3 versions. It requires the following packages:

`pip3 install flask pyyaml sqlobject`

Then 

- Fetch web dependencies using `yarn install` in `quic_tracker/static`

- Add the project root directory to `$PYTHONPATH` using `export PYTHONPATH=$PYTHONPATH:$PWD`

- Start the application with `python3 quic_tracker/app.py`

- Output from the scenario runner should be placed into `quic_tracker/traces` with a name in the format `\d*.json`