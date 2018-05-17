from datetime import datetime

from quic_tracker.postprocess.common import register


@register('ack_only','connection_migration','flow_control','handshake','handshake_retransmission','handshake_v6','http_get_and_wait','http_get_on_uni_stream','multi_stream','new_connection_id','padding','stop_sending_frame_on_receive_stream','stream_opening_reordering','transport_parameters','unsupported_tls_version','version_negotiation','zero_rtt')
def scenario_failures(traces):

    yield('Date', 'Failures')

    for d, failures in sorted(sum_traces(traces, lambda t: t['error_code'] != 0).items(), key=lambda x: x[0]):
        yield (d.isoformat(), failures)


@register('ack_only','connection_migration','flow_control','handshake','handshake_retransmission','handshake_v6','http_get_and_wait','http_get_on_uni_stream','multi_stream','new_connection_id','padding','stop_sending_frame_on_receive_stream','stream_opening_reordering','transport_parameters','unsupported_tls_version','version_negotiation','zero_rtt')
def scenario_success(traces):

    yield('Date', 'Success')

    for d, failures in sorted(sum_traces(traces, lambda t: t['error_code'] == 0).items(), key=lambda x: x[0]):
        yield (d.isoformat(), failures)


def sum_traces(traces, threshold):
    marked = set()
    results = {}

    for t in traces:
        date = datetime.fromtimestamp(t['started_at']).date()

        if (date, t['host']) in marked:
            continue

        if threshold(t):
            results[date] = results.get(date, 0) + 1
        marked.add((date, t['host']))

    return results
