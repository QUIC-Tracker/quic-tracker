import os
import json
import re

from datetime import date, datetime
from flask import Flask
from flask.templating import render_template


def get_root_path():
    return os.path.abspath(os.path.dirname(__file__))


def join_root(*paths):
    return os.path.join(get_root_path(), *paths)

app = Flask(__name__)


def parse_alt_svc(header_value):
    regex = r"([^\";,\s]*=\"?[^\";]*\"?)"
    advertise_gquic = False
    advertise_ietf_quic = False
    versions = set()
    for v in (m.group(1) for m in re.finditer(regex, header_value)):
        if v.startswith('quic="'):
            advertise_gquic = True
        elif v.startswith('v="'):
            for version in re.match(r'v=\"(.*)\"', v).group(1).split(','):
                print(version)
                try:
                    versions.add(int(version))
                except ValueError:
                    pass
        elif v.startswith('hq'):
            version = re.match(r'(hq-[0-9](?:-?.*)*)=\"(.*)\"', v).group(1)
            versions.add(version)
    return advertise_gquic, advertise_ietf_quic, versions


def compute_stats(records):
    gquic_advertisements = 0
    ieft_quic_advertisements = 0
    ipv6_supports = 0
    unique_versions = set()
    for record in records:
        alt_svc_value = record.get('ipv4', record.get('ipv6', {})).get('Alt-Svc') or ''
        advertise_gquic, advertise_ietf_quic, versions = parse_alt_svc(alt_svc_value)
        unique_versions |= versions
        if advertise_gquic:
            gquic_advertisements += 1
        if advertise_ietf_quic:
            ieft_quic_advertisements += 1
        if record.get('ipv6', {}).get('peer'):
            ipv6_supports += 1
    return gquic_advertisements, ieft_quic_advertisements, ipv6_supports, unique_versions


@app.route('/')
def index():
    return result(date.today().strftime('%Y%m%d'))


@app.route('/result/<int:d>')
def result(d):
    with open(join_root('data', '%s.json' % d)) as f:
        records = json.load(f)
        return render_template('result.html', records=records, date=datetime.strptime(d, '%Y%m%d').date(), stats=compute_stats(records))


if __name__ == '__main__':
    app.run(debug=True)
