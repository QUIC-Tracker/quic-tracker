import sys
from http.client import HTTPException
from ssl import CertificateError
from urllib.error import HTTPError, URLError
from urllib.request import urlopen, Request


def scrape_domain(protocol, domain, user_agent='Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:54.0) Gecko/20100101 Firefox/54.0'):
    url = '%s://%s' % (protocol, domain)
    try:
        request = Request(url, headers={'User-Agent': user_agent})
        with urlopen(request, timeout=5) as response:
            return url, response.info().get('Alt-Svc')
    except HTTPError as e:
        return url, e.headers.get('Alt-Svc')
    except (URLError, CertificateError, HTTPException):
        if protocol == 'https':
            return scrape_domain('http', domain)
    except OSError as e:
        print(url, e)
    return url, None

if __name__ == "__main__":
    domain_list_filename = sys.argv[1]
    with open(domain_list_filename) as domain_list_file:
        domain_list = domain_list_file.read().strip()
    for domain in domain_list.splitlines():
        url, header_value = scrape_domain('https', domain)
        print(url, header_value)

