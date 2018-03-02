import os
from json import JSONEncoder


def get_root_path():
    return os.path.abspath(os.path.dirname(__file__))


def join_root(*paths):
    return os.path.join(get_root_path(), *paths)


def find_latest_result_file():
    return filter(lambda s: s.replace('.json', '').isdigit(), sorted(os.listdir(join_root('data')), reverse=True)).__next__()


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
