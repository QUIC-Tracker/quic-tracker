import sys
from ssl import CertificateError
from urllib.error import HTTPError
from urllib.request import urlopen, Request

if __name__ == "__main__":
    url_list_filename = sys.argv[1]
    with open(url_list_filename) as url_list_file:
        url_list = url_list_file.read().strip()
    for url in url_list.splitlines():
        print(url, end='\t')
        try:
            request = Request(url, headers={'User-Agent': 'Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:54.0) Gecko/20100101 Firefox/54.0'})
            response_headers = urlopen(url, timeout=5).info()
            if 'Alt-Svc' in response_headers:
                print('Alt-Svc: %s' % urlopen(url).info()['Alt-Svc'], end='')
        except HTTPError as e:
            print(e, end='')
        except (OSError, CertificateError) as e:
            print(e, end='')
        print()
