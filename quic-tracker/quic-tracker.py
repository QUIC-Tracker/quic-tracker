import os
import re
from datetime import datetime

from flask import Flask, jsonify
from flask import request
from flask import url_for
from flask.templating import render_template
from sqlobject import LIKE
from sqlobject import OR
from sqlobject import sqlhub

from database import setup_database, SQLObjectThreadConnection, Results, load_results, Record, records_to_datatables_data
from utils import find_latest_results_file

app = Flask(__name__)
setup_database()


@app.before_request
def setup_thread_request():
    sqlhub.threadConnection = SQLObjectThreadConnection.get_conn()


def compute_stats(result):
    gquic_advertisements = 0
    ieft_quic_advertisements = 0
    ipv6_supports = 0
    unique_versions = set()
    versions_count = {}
    # TODO: Make it compute using SQL
    return gquic_advertisements, ieft_quic_advertisements, ipv6_supports, unique_versions, versions_count


@app.route('/')
def index():
    return results(int(os.path.splitext(find_latest_results_file())[0]))


@app.route('/results/<int:d>')
def results(d):
    r = Results.selectBy(date=d).getOne(None)
    if r is None:
        r = sqlhub.doInTransaction(load_results, d)
    return render_template('result.html', records_length=len(r.records), date=datetime.strptime(str(d), '%Y%m%d').date(),
                           stats=compute_stats(list(r.records)), ajax_url=url_for('results_data', d=d))


@app.route('/results/<int:d>/data')
def results_data(d):
    r = Results.selectBy(date=d).getOne(None)
    if r is None:
        r = load_results(d)

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
    records = Record.selectBy(results=r).orderBy(ordering_col)

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

if __name__ == '__main__':
    app.run(debug=True)
