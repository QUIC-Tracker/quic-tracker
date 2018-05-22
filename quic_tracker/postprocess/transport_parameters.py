import itertools
from base64 import b64decode
from datetime import datetime

from quic_tracker.postprocess.common import register, host_to_name

_version_to_p_name = {
    0xff000007: {
        0: 'initial_max_stream_data',
        1: 'initial_max_data',
        2: 'initial_max_stream_id',
        3: 'idle_timeout',
        4: 'omit_connection_id',
        5: 'max_packet_size',
        6: 'stateless_reset_token',
    },
    0xff000008: {
        0: 'initial_max_stream_data',
        1: 'initial_max_data',
        2: 'initial_max_stream_id_bidi',
        3: 'idle_timeout',
        4: 'omit_connection_id',
        5: 'max_packet_size',
        6: 'stateless_reset_token',
        7: 'ack_delay_exponent',
        8: 'initial_max_stream_id_uni'
    },
    0xff000011: {
        0: 'initial_max_stream_data',
        1: 'initial_max_data',
        2: 'initial_max_stream_id_bidi',
        3: 'idle_timeout',
        5: 'max_packet_size',
        6: 'stateless_reset_token',
        7: 'ack_delay_exponent',
        8: 'initial_max_stream_id_uni'
    }
}

for tp in set(itertools.chain.from_iterable(tp_def.values() for tp_def in _version_to_p_name.values())):

    def get_tp_handler(tp):
        def tp_handler(traces):
            results = sum_traces(traces)

            endpoints = list(sorted(set(t['host'] for t in traces)))
            endpoints = list(filter(lambda e: any(tp in date_r.get(e, {}) for date_r in results.values()), endpoints))

            yield ('Date', *(host_to_name[e] for e in endpoints))

            for d, parameters in sorted(results.items(), key=lambda x: x[0]):
                yield (d.isoformat(), *(parameters.get(e, {}).get(tp, 'nan') for e in endpoints))

        return tp_handler

    func = get_tp_handler(tp)
    func.__name__ = 'transport_parameters_' + tp
    register('transport_parameters')(func)


def sum_traces(traces):
    marked = set()
    results = {}

    for t in traces:
        date = datetime.fromtimestamp(t['started_at']).date()

        if (date, t['host']) in marked or 'transport_parameters' not in t['results']:
            continue

        date_parameters = results.get(date, {})
        parameters = date_parameters.get(t['host'], {})
        trace_parameters = t['results']['transport_parameters']
        version = trace_parameters['NegotiatedVersion']
        for p in trace_parameters['Parameters']:
            p_type, p_value = parse_parameter(p["ParameterType"], p["Value"], version)
            parameters[p_type] = p_value

        date_parameters[t['host']] = parameters
        results[date] = date_parameters

        marked.add((date, t['host']))

    return results


def parse_parameter(p_type, p_value, version):
    if version <= 0xff000007:
        p_type = _version_to_p_name[0xff000007][p_type]
    if 0xff000008 <= version <= 0xff000010:
        p_type = _version_to_p_name[0xff000008][p_type]
    else:
        print(version)
        p_type = _version_to_p_name[0xff000011][p_type]

    return p_type, int.from_bytes(b64decode(p_value), byteorder='big')


