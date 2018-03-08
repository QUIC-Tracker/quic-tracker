import os
import re
import json
from datetime import datetime

import yaml
from flask import Flask, jsonify, request, url_for, abort
from flask import redirect
from flask.templating import render_template
from sqlobject import LIKE
from sqlobject import OR
from sqlobject import sqlhub

from quic_tracker.database import setup_database, SQLObjectThreadConnection, Result, load_result, Record, records_to_datatables_data
from quic_tracker.traces import get_example_trace, get_traces, parse_trace
from quic_tracker.utils import find_latest_file, ByteArrayEncoder, is_tuple, decode, join_root

app = Flask(__name__)
setup_database()
app.json_encoder = ByteArrayEncoder
app.jinja_env.filters['is_tuple'] = is_tuple
app.jinja_env.filters['decode'] = decode
app.jinja_env.filters['pretty_json'] = lambda x: json.dumps(x, indent=2, separators=(',', ':'))
app.jinja_env.filters['timestamp'] = lambda x: datetime.fromtimestamp(x)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['EXPLAIN_TEMPLATE_LOADING'] = True


@app.before_request
def setup_thread_request():
    sqlhub.threadConnection = SQLObjectThreadConnection.get_conn()

_stats_cache = {}


def compute_stats(result):
    if result.id not in _stats_cache:
        gquic_advertisements = Record.selectBy(result=result, advertise_gquic=True).count()
        ieft_quic_advertisements = Record.selectBy(result=result, advertise_ietf_quic=True).count()
        ipv6_supports = Record.selectBy(result=result).filter(Record.q.ipv6 != None).count()
        unique_versions = set(sv.version for sv in Record.selectBy(result=result).throughTo.supported_versions.distinct())
        versions_count = dict(sqlhub.threadConnection.queryAll('SELECT version, count(version) FROM record R JOIN supported_version SV ON R.id = SV.record_id WHERE R.result_id = %d GROUP BY version' % result.id))
        _stats_cache[result.id] = gquic_advertisements, ieft_quic_advertisements, ipv6_supports, unique_versions, versions_count
    return _stats_cache[result.id]


@app.route('/')
def index():
    return redirect(url_for('test_suite'))


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/tracker')
def tracker():
    return results(int(os.path.splitext(find_latest_file('data'))[0]))


@app.route('/tracker/results/<int:d>')
def results(d):
    r = Result.selectBy(date=d).getOne(None)
    if r is None:
        r = sqlhub.doInTransaction(load_result, d)
    return render_template('result.html', records_length=Record.selectBy(result=r).count(), date=datetime.strptime(str(d), '%Y%m%d').date(),
                           stats=compute_stats(r), ajax_url=url_for('results_data', d=d))


@app.route('/tracker/results/<int:d>/data')
def results_data(d):
    r = Result.selectBy(date=d).getOne(None)
    if r is None:
        r = load_result(d)

    args = {}
    for key, value in request.args.items(multi=True):
        matches = re.compile(r'(\w+)(?:(?:\[(?:\w+)\])*?)').findall(key)
        try:
            value = int(value)
        except ValueError:
            pass
        d = args
        for m in matches[:-1]:
            try:
                m = int(m)
            except ValueError:
                pass
            if m not in d:
                d[m] = {}
            d = d[m]
        if value in ('true', 'false'):
            value = value == 'true'
        key = matches[-1]
        if key in d:
            v = d[key]
            if type(v) is list:
                v.append(value)
            else:
                d[key] = [v, value]
        else:
            d[key] = value

    columns = ['id', 'url', 'ipv4', 'header_v4', 'ipv6', 'header_v6']
    ordering_col = ('-' if args['order'][0]['dir'] == 'desc' else '') + columns[args['order'][0]['column']]
    records = Record.selectBy(result=r).orderBy(ordering_col)

    search_value = str(args['search']['value']).strip()
    if search_value:
        records = records.filter(OR(LIKE(Record.q.url, '%%%s%%' % search_value),
                                    LIKE(Record.q.ipv4, '%%%s%%' % search_value),
                                    LIKE(Record.q.header_v4, '%%%s%%' % search_value),
                                    LIKE(Record.q.ipv6, '%%%s%%' % search_value),
                                    LIKE(Record.q.header_v6, '%%%s%%' % search_value)))

    total = Record.select().count()
    filtered = records.count()
    records = records[args['start']:args['start']+args['length']]

    response = {'draw': int(args['draw']),  # Prevents XSS through draw value
                'recordsTotal': total,
                'recordsFiltered': filtered,
                'data': records_to_datatables_data(records)}

    return jsonify(response)


@app.route('/traces')
def test_suite():
    return traces(int(os.path.splitext(find_latest_file('traces'))[0]))


@app.route('/traces/<int:traces_id>')
def traces(traces_id):
    traces = get_traces(traces_id)
    if traces is None:
        abort(404)

    with open(join_root('scenarii.yaml')) as f:
        scenarii = yaml.load(f)

    return render_template('traces.html', traces_id=traces_id, traces=traces, date=datetime.strptime(str(traces_id), '%Y%m%d').date(), scenarii=scenarii)


@app.route('/traces/<int:traces_id>/<int:trace_idx>')
def dissector(traces_id, trace_idx):
    traces = get_traces(traces_id)
    if traces is None:
        abort(404)

    with open(join_root('protocol.yaml')) as f:
        protocol = yaml.load(f)

    with open(join_root('scenarii.yaml')) as f:
        scenarii = yaml.load(f)

    trace = parse_trace(traces[trace_idx], protocol)
    return render_template('dissector.html', trace=trace, scenario=scenarii[trace['scenario']])


if __name__ == '__main__':
    app.run(debug=True)
