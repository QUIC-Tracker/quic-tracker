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

import os
from json import JSONEncoder


def get_root_path():
    return os.path.abspath(os.path.dirname(__file__))


def join_root(*paths):
    return os.path.join(get_root_path(), *paths)


def find_data_files(directory, reverse=True):
    return filter(lambda s: s.replace('.json', '').isdigit(), sorted(os.listdir(join_root(directory)), reverse=reverse))


def find_latest_file(directory):
    return next(find_data_files(directory))


def find_previous_file(id, directory):
    return next(filter(lambda d: int(d.replace('.json', '')) < id, find_data_files(directory)), None)


def find_next_file(id, directory):
    return next(filter(lambda d: int(d.replace('.json', '')) > id, find_data_files(directory, reverse=False)), None)


class ByteArrayEncoder(JSONEncoder):

    def default(self, obj):
        if isinstance(obj, bytearray):
            return obj.hex()
        else:
            return JSONEncoder.default(self, obj)


def is_tuple(value):
    return isinstance(value, tuple)


def split_every_n(string, n=2):
    return [''.join(x) for x in zip(*[iter(string)]*n)]


def decode(hex_byte):
    c = chr(int('0x' + hex_byte, base=16))
    return c if c.isprintable() else '.'
