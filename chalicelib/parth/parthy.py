# import argparse
import concurrent.futures
import json

from .core.colors import green, white, end, info, bad, good, run
from .core.importer import importer
from .core.scanner import scanner
from .core.utils import save_result

from .plugins.commoncrawl import commoncrawl
from .plugins.otx import otx
from .plugins.wayback import wayback

# parser = argparse.ArgumentParser() # defines the parser
# Arguments that can be supplied
# parser.add_argument('-t', help='target host', dest='host')
# parser.add_argument('-i', help='import from file', dest='input_file')
# parser.add_argument('-u', help='uniq parameters', dest='dupes', action='store_true')
# parser.add_argument('-f', help='output format', dest='output_format', default='json')
# parser.add_argument('-p', help='save parameters', dest='save_params', action='store_true')
# args = parser.parse_args() # arguments to be parsed

class Parth:
    def __init__(self, target="pichau.com.br"):
        self.target = target
        self.results = []

    def fetch_urls(self):
        available_plugins = {'commoncrawl': commoncrawl, 'otx': otx, 'wayback': wayback}
        page = 0
        progress = 0
        requests = {}
        while len(available_plugins) > 0 and page <= 10:
            threadpool = concurrent.futures.ThreadPoolExecutor(max_workers=len(available_plugins))
            futures = (threadpool.submit(func, self.target, page) for func in available_plugins.values())
            for each in concurrent.futures.as_completed(futures):
                if progress < 98:
                    progress += 3
                this_result = each.result()
                if not this_result[1]:
                    progress += ((10 - page) * 10 / 3)
                    del available_plugins[this_result[2]]
                for url in this_result[0]:
                    requests[url] = []
                print('%s Progress: %i%%' % (info, progress), end='\r')
            page += 1
        print('%s Progress: %i%%' % (info, 100), end='\r')
        return requests

    def main(self):
        all_params = []
        requests = None
        requests = self.fetch_urls()

        if requests:
            result, all_params = scanner(requests, False, False)
            for each in result:
                # print('%s+%s %s' % (green, end, each['url']))
                # print('    %s- issues:%s   %s' % (green, end, ', '.join(each['issues'])))
                # print('    %s- location:%s %s' % (green, end, each['location']))
                # if each['data']:
                #     print('%s- data:%s %s' % (green, end, each['data']))
                self.results.append({
                    "url": each['url'],
                    "issues": ', '.join(each['issues']),
                    "location": each['location'],
                    "data": each['data'] ,
                })
        else:
            self.results.append({
                "message": "No host specified"
            })

        print(self.results)

        return {
            "result": self.results
        }