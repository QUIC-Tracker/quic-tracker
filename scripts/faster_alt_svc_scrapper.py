import json
import sys
from socket import AF_INET, AF_INET6

import aiohttp
import asyncio


# Taken from https://gist.github.com/aubricus/f91fb55dc6ba5557fbab06119420dd6a, considered as public domain.
def print_progress(iteration, total, prefix='', suffix='', decimals=1, bar_length=100):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        bar_length  - Optional  : character length of bar (Int)
    """
    str_format = "{0:." + str(decimals) + "f}"
    percents = str_format.format(100 * (iteration / float(total)))
    filled_length = int(round(bar_length * iteration / float(total)))
    bar = '█' * filled_length + '-' * (bar_length - filled_length)

    print('\r%s |%s| %s%s %s' % (prefix, bar, percents, '%', suffix), end='')

    if iteration == total:
        print()


def get_record(url, results):
    peer4, header4, peer6, header6 = results
    record = {'url': url}
    if peer4 and all(*peer4):
        record['ipv4'] = {'peer': {'host': peer4[0], 'port': peer4[1]}, 'Alt-Svc': header4}
    if peer6 and all(*peer6):
        record['ipv6'] = {'peer': {'host': peer6[0], 'port': peer6[1]}, 'Alt-Svc': header6}
    return record


async def scrape(url, user_agent='Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:54.0) Gecko/20100101 Firefox/54.0'):
    async def do_request(conn):
        try:
            async with aiohttp.ClientSession(headers={'User-Agent': user_agent}, read_timeout=5, conn_timeout=5, connector=conn) as session:
                async with session.get(url, allow_redirects=False) as resp:  # TODO: Establish a policy for HTTP redirects
                    record = list(conn.cached_hosts.values())[0][0]
                    return (record['host'], record['port']), resp.headers.get('Alt-Svc')
        except aiohttp.ClientConnectorError:
            return (None, None), None
    peer4, header4 = await do_request(aiohttp.TCPConnector(family=AF_INET))
    peer6, header6 = await do_request(aiohttp.TCPConnector(family=AF_INET6))
    return peer4, header4, peer6, header6

if __name__ == "__main__":
    domain_list_filename = sys.argv[1]
    max_events = int(sys.argv[2])
    output_file = sys.argv[3]
    with open(domain_list_filename) as domain_list_file:
        domain_list = domain_list_file.read().strip()
        domains = domain_list.splitlines()
        domains.reverse()

    loop = asyncio.get_event_loop()
    tasks_finished = [False] * max_events
    count = 0
    results = [None] * len(domains)

    for i, domain in enumerate(domains[:max_events]):
        def enqueue_next_domain(i, protocol='https'):
            def enqueue(previous_task):
                global count
                if previous_task is not None:
                    try:
                        results[previous_task.index] = get_record(previous_task.url, previous_task.result())
                    except Exception as e:
                        # Prettify error in the output ?
                        results[previous_task.index] = get_record(previous_task.url, (None,) * 4)
                        results[previous_task.index]['error'] = str(e)
                    count += 1
                    print_progress(count, len(results))

                if domains:
                    domain = domains.pop()
                    url = '%s://%s' % (protocol, domain)
                    task = asyncio.run_coroutine_threadsafe(scrape(url), loop)
                    task.url = url
                    task.index = i
                    task.add_done_callback(enqueue_next_domain(i + max_events))
                else:
                    tasks_finished[i % max_events] = True
                    if all(tasks_finished):
                        loop.stop()
                        with open(output_file, 'w') as f:
                            json.dump(results, f)
            return enqueue
        enqueue_next_domain(i)(None)

    loop.run_forever()
