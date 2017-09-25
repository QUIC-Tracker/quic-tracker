import ssl
import sys
import aiohttp
import asyncio

async def scrape(url, user_agent='Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:54.0) Gecko/20100101 Firefox/54.0'):
    async with aiohttp.ClientSession(headers={'User-Agent': user_agent}, read_timeout=5, conn_timeout=5) as session:
        async with session.get(url, allow_redirects=url.startswith('https')) as resp:
            return resp.headers.get('Alt-Svc')

if __name__ == "__main__":
    domain_list_filename = sys.argv[1]
    max_events = int(sys.argv[2])
    with open(domain_list_filename) as domain_list_file:
        domain_list = domain_list_file.read().strip()
        domains = domain_list.splitlines()

    loop = asyncio.get_event_loop()
    tasks_finished = [False] * max_events

    for i, domain in enumerate(domains[:max_events]):
        def enqueue_next_domain(i, protocol='https'):
            def enqueue(previous_task):
                if previous_task is not None:
                    try:
                        print(previous_task.url, previous_task.result())
                    except ssl.CertificateError:
                        return enqueue_next_domain(previous_task.index, protocol='http')(None)
                    except Exception:
                        print(previous_task.url, None)

                if i < len(domains):
                    domain = domains[i]
                    url = '%s://%s' % (protocol, domain)
                    task = asyncio.run_coroutine_threadsafe(scrape(url), loop)
                    task.url = url
                    task.index = i
                    task.add_done_callback(enqueue_next_domain(i + max_events))
                else:
                    tasks_finished[i % max_events] = True
                    if all(tasks_finished):
                        loop.stop()
            return enqueue
        enqueue_next_domain(i)(None)

    loop.run_forever()
