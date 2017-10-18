import os
import re
from datetime import datetime

from flask import Flask
from flask.templating import render_template
from sqlobject import sqlhub

from database import setup_database, SQLObjectThreadConnection, Results, load_results
from utils import find_latest_results_file

app = Flask(__name__)
setup_database()


@app.before_request
def setup_thread_request():
    sqlhub.threadConnection = SQLObjectThreadConnection.get_conn()


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
                try:
                    versions.add(int(version))
                except ValueError:
                    pass
        elif v.startswith('hq'):
            version = re.match(r'(hq-[0-9](?:-?.*)*)=\"(.*)\"', v).group(1)
            versions.add(version)
    return advertise_gquic, advertise_ietf_quic, versions


def compute_stats(records):  # TODO: Make it compute using SQL
    gquic_advertisements = 0
    ieft_quic_advertisements = 0
    ipv6_supports = 0
    unique_versions = set()
    versions_count = {}
    for record in records:
        alt_svc_value = (record.header_v4 if record.ipv4 else record.header_v6) or ''
        advertise_gquic, advertise_ietf_quic, versions = parse_alt_svc(alt_svc_value)
        unique_versions |= versions
        if advertise_gquic:
            gquic_advertisements += 1
        if advertise_ietf_quic:
            ieft_quic_advertisements += 1
        if record.ipv6:
            ipv6_supports += 1
        for v in versions:
            versions_count[v] = versions_count.get(v, 0) + 1
    return gquic_advertisements, ieft_quic_advertisements, ipv6_supports, unique_versions, versions_count


@app.route('/')
def index():
    return results(int(os.path.splitext(find_latest_results_file())[0]))


@app.route('/results/<int:d>')
def results(d):
    r = Results.selectBy(date=d).getOne(None)
    if r is None:
        r = load_results(d)
    return render_template('result.html', records=r.records, date=datetime.strptime(str(d), '%Y%m%d').date(),
                           stats=compute_stats(r.records))


if __name__ == '__main__':
    app.run(debug=True)
