from datetime import datetime
from datetime import date

from quic_tracker.postprocess.common import register, host_to_name


@register('handshake_retransmission')
def amplification_factor(traces):
    marked = set()
    results = {}

    for t in traces:
        date = datetime.fromtimestamp(t['started_at']).date()

        if (date, t['host']) in marked:
            continue

        if 'amplification_factor' in t['results'] and (t['error_code'] > 3 or t['error_code'] == 0):
            amplification_factors = results.get(date, {})
            amplification_factors[t['host']] = t['results']['amplification_factor']
            results[date] = amplification_factors

        marked.add((date, t['host']))

    endpoints = list(sorted(set(t['host'] for t in traces)))
    endpoints = list(filter(lambda e: any(date_r.get(e, 0) > 0 for date_r in results.values()), endpoints))

    yield ('Date', *(host_to_name[e] for e in endpoints))

    for d, parameters in sorted(results.items(), key=lambda x: x[0]):
        yield (d.isoformat(), *(parameters.get(e, 'nan') for e in endpoints))


@register('handshake_retransmission')
def handshake_retransmission_timer(traces):
    marked = set()
    results = {}

    for t in traces:
        d = datetime.fromtimestamp(t['started_at']).date()

        if (d, t['host']) in marked:
            continue

        if len(t['results'].get('arrival_times') or []) > 1:
            arrival_times = results.get(d, {})
            arrival_times[t['host']] = t['results']['arrival_times']
            results[d] = arrival_times

        marked.add((d, t['host']))

    yield ('# ' + str(date(2018, 3, 19)),)
    yield from get_day(results, date(2018, 3, 19))
    yield ('# ' + str(date(2018, 5, 21)),)
    yield from get_day(results, date(2018, 5, 21))


def get_day(results, d):
    yield ('Packet', *(host_to_name[e] for e in results[d]))

    for i in range(len(sorted(results[d].values(), key=lambda x: -len(x))[0])):
        yield (str(i), *(str(retransmissions[i]) if i < len(retransmissions) else 'nan' for _, retransmissions in results[d].items()))