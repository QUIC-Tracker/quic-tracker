#
#   Maxime Piraux's master's thesis
#   Copyright (C) 2017-2018  Maxime Piraux
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU Affero General Public License version 3
#   as published by the Free Software Foundation.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU Affero General Public License for more details.
#
#   You should have received a copy of the GNU Affero General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

import json
import tempfile
import threading

import re
from sqlobject import SQLObject, IntCol, StringCol, ForeignKey, sqlhub, MultipleJoin, sqlbuilder, BoolCol
from sqlobject.sqlbuilder import Insert
from sqlobject.sqlite.sqliteconnection import SQLiteConnection
from quic_tracker.utils import join_root

database_file = tempfile.mkstemp()[1]


def setup_database():
    sqlhub.processConnection = create_connection()
    Result.createTable()
    Record.createTable()
    SupportedVersion.createTable()


def create_connection():
    conn = SQLiteConnection(database_file)
    conn.queryOne('PRAGMA JOURNAL_MODE = OFF;')
    conn.queryOne('PRAGMA SYNCHRONOUS = OFF;')
    return conn


class Result(SQLObject):
    date = IntCol(notNone=True)
    records = MultipleJoin('Record')


class Record(SQLObject):
    result = ForeignKey('Result', notNone=True)
    url = StringCol(notNone=True)
    ipv4 = StringCol(default=None)
    header_v4 = StringCol(default=None)
    ipv6 = StringCol(default=None)
    header_v6 = StringCol(default=None)
    error = StringCol(default=None)

    advertise_gquic = BoolCol(default=False)
    advertise_ietf_quic = BoolCol(default=False)
    supported_versions = MultipleJoin('SupportedVersion')

    class sqlmeta:
        lazyUpdate = True


class SupportedVersion(SQLObject):
    record = ForeignKey('Record', notNone=True)
    version = StringCol(notNone=True)


class SQLObjectThreadConnection(object):
    _local = threading.local()

    @classmethod
    def get_conn(cls):
        if 'conn' not in cls._local.__dict__:
            cls._local.conn = create_connection()
        return cls._local.conn


def parse_alt_svc(header_value):
    regex = r"([^\";,\s]+=([^\",;]+|\"[^\";]+\"))"
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
        elif v.startswith('hq-'):
            version = re.match(r'(hq-[0-9](?:-?.*)*)=\"(.*)\"', v).group(1)
            versions.add(version)
    return advertise_gquic, advertise_ietf_quic, versions


def load_result(date):
    result = Result(date=date)
    conn = sqlhub.threadConnection
    with open(join_root('data', '%s.json' % date)) as f:
        records = json.load(f)
    records_values = []
    for record in records:
        record_dict = {'result_id': result.id,
                       'url': record['url'],
                       'ipv4': record.get('ipv4', {}).get('peer', {}).get('address'),
                       'header_v4': record.get('ipv4', {}).get('Alt-Svc'),
                       'ipv6': record.get('ipv6', {}).get('peer', {}).get('address'),
                       'header_v6': record.get('ipv6', {}).get('Alt-Svc')}
        records_values.append(record_dict)

    insert = Insert('record', valueList=records_values, template=('result_id', 'url', 'ipv4', 'header_v4', 'ipv6', 'header_v6'))
    conn.query(conn.sqlrepr(insert))

    for r in Record.selectBy(result=result):
        alt_svc_value = (r.header_v4 if r.ipv4 else r.header_v6) or ''
        advertise_gquic, advertise_ietf_quic, versions = parse_alt_svc(alt_svc_value)

        if advertise_gquic or advertise_ietf_quic:
            r.advertise_gquic = advertise_gquic
            r.advertise_ietf_quic = advertise_ietf_quic
            r.syncUpdate()
        for v in versions:
            SupportedVersion(record=r, version=str(v))

    return result


def records_to_datatables_data(records):
    return [[r.id, r.url, r.ipv4, r.header_v4, r.ipv6, r.header_v6] for r in records]
