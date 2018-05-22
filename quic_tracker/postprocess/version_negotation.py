import itertools
from base64 import b64decode
from datetime import datetime

from quic_tracker.postprocess.common import register


@register('version_negotiation')
def draft_versions(traces):
    all_versions = get_versions(traces)

    unique_versions = set(itertools.chain.from_iterable(iter(all_versions[r].keys()) for r in all_versions))
    unique_versions = sorted(set(filter(lambda v: v & 0xffffff00 == 0xff000000, unique_versions)))

    yield ('Date', *unique_versions)

    for d, versions in sorted(all_versions.items(), key=lambda x: x[0]):
        yield (d.isoformat(), *(versions.get(v, 0) for v in unique_versions))


@register('version_negotiation')
def number_of_endpoints(traces):
    marked = set()
    results = {}

    for t in traces:
        date = datetime.fromtimestamp(t['started_at']).date()

        if (date, t['host']) in marked:
            continue

        results[date] = results.get(date, 0) + 1
        marked.add((date, t['host']))

    yield ('Date', 'Endpoints')

    for d, endpoints in sorted(results.items(), key=lambda x: x[0]):
        yield (d.isoformat(), endpoints)


def get_versions(traces):
    marked = set()
    results = {}

    for t in traces:
        date = datetime.fromtimestamp(t['started_at']).date()

        if (date, t['host']) in marked:
            continue

        if 'supported_versions' not in t['results']:
            t['results']['supported_versions'] = set()
            for p in t['stream']:
                if p['direction'] == 'to_client':
                    t['results']['supported_versions'].update(read_version_negotiation_packet(b64decode(p['data'])))

        versions = results.get(date, {})
        for v in t['results']['supported_versions']:
            versions[v] = versions.get(v, 0) + 1

        if len(t['results']['supported_versions']) == 0:
            for p in t['stream']:
                read_version_negotiation_packet(p['data'])

        results[date] = versions
        marked.add((date, t['host']))

    return results


def read_version_negotiation_packet(data):
    """ Fixes missing supported_versions after draft-11 update. """
    if data[1:5] != b'\x00\x00\x00\x00':
        return []

    def get_offset(CIL):
        return (CIL + 3) if CIL > 0 else 0

    version_offset = 6 + get_offset((data[5] & 0xf0) >> 4) + get_offset(data[5] & 0xf)

    while version_offset < len(data):
        yield int.from_bytes(data[version_offset:version_offset+4], byteorder='big')
        version_offset += 4

