import json
import os
import sys
from json import JSONDecodeError

from quic_tracker.postprocess.common import functions
import quic_tracker.postprocess.version_negotation
import quic_tracker.postprocess.failures
import quic_tracker.postprocess.transport_parameters
import quic_tracker.postprocess.handshake_retransmission
import quic_tracker.postprocess.handshake

if __name__ == "__main__":
    traces_dir = sys.argv[1]
    output_dir = sys.argv[2]

    traces = []

    for filename in os.listdir(traces_dir):
        path = os.path.join(traces_dir, filename)
        if os.path.isfile(path):
            with open(os.path.join(traces_dir, filename)) as f:
                try:
                    traces.extend(json.load(f))
                except (TypeError, JSONDecodeError) as e:
                    print("Error when reading {}: {}".format(filename, e))

    for s, functions in functions.items():
        s_traces = list(filter(lambda t: t['scenario'] == s, traces))
        for f in functions:
            function_dir = os.path.join(output_dir, f.__name__)
            if not os.path.exists(function_dir):
                os.mkdir(function_dir)
            with open(os.path.join(function_dir, '{}_{}.csv'.format(f.__name__, s)), 'w') as file:
                for l in f(s_traces):
                    file.write(','.join(str(e) for e in l)+'\n')

