import json
import tempfile
import threading

from sqlobject import SQLObject, IntCol, StringCol, ForeignKey, sqlhub, MultipleJoin
from sqlobject.sqlite.sqliteconnection import SQLiteConnection

from utils import join_root

database_file = tempfile.mkstemp()[1]


def setup_database():
    sqlhub.processConnection = create_connection()
    Results.createTable()
    Record.createTable()


def create_connection():
    return SQLiteConnection(database_file)


class Results(SQLObject):
    date = IntCol(notNone=True)
    records = MultipleJoin('Record')


class Record(SQLObject):
    results = ForeignKey('Results', notNone=True)
    url = StringCol(notNone=True)
    ipv4 = StringCol(default=None)
    header_v4 = StringCol(default=None)
    ipv6 = StringCol(default=None)
    header_v6 = StringCol(default=None)
    error = StringCol(default=None)


class SQLObjectThreadConnection(object):
    _local = threading.local()

    @classmethod
    def get_conn(cls):
        if 'conn' not in cls._local.__dict__:
            cls._local.conn = create_connection()
        return cls._local.conn


def load_results(date):
    results = Results(date=date)
    with open(join_root('data', '%s.json' % date)) as f:
        records = json.load(f)
        for record in records:
            Record(results=results, url=record['url'], ipv4=record.get('ipv4', {}).get('peer', {}).get('address'),
                   header_v4=record.get('ipv4', {}).get('Alt-Svc'),
                   ipv6=record.get('ipv6', {}).get('peer', {}).get('address'),
                   header_v6=record.get('ipv6', {}).get('Alt-Svc'))
    return results
