import os


def get_root_path():
    return os.path.abspath(os.path.dirname(__file__))


def join_root(*paths):
    return os.path.join(get_root_path(), *paths)


def find_latest_result_file():
    return sorted(os.listdir(join_root('data')), reverse=True)[0]
