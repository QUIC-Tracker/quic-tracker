import itertools
from datetime import datetime

from quic_tracker.postprocess.common import register


@register('handshake')
def handshake_versions(traces):
    marked = set()
    results = {}

    for t in traces:
        date = datetime.fromtimestamp(t['started_at']).date()

        if (date, t['host']) in marked:
            continue

        if t['error_code'] == 0:
            v = t['results']['negotiated_version']
            versions = results.get(date, {})
            versions[v] = versions.get(v, 0) + 1
            results[date] = versions

        marked.add((date, t['host']))

    unique_versions = set(itertools.chain.from_iterable(iter(results[r].keys()) for r in results))
    unique_versions = sorted(set(filter(lambda v: v & 0xffffff00 == 0xff000000, unique_versions)))

    yield ('Date', *unique_versions)

    for d, versions in sorted(results.items(), key=lambda x: x[0]):
        yield (d.isoformat(), *(versions.get(v, 0) for v in unique_versions))

