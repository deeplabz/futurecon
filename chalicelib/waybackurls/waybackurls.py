from core import requester
from urllib.parse import unquote 
import requests
import re
import argparse
import os
import sys
import time 
start_time = time.time()


def main(domain=[]):
    if os.name == 'nt':
        os.system('cls')

    target = domain
    results = []
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=txt&fl=original&collapse=urlkey&page=/"

    response = requester.connector(url)
    if response == False:
        return
    response = unquote(response)
    
    final_uris = response

    file = open("temp.txt","w")
    file.write(final_uris)
    file.close
    file = open("temp.txt","r")
    uris = file.read().splitlines()

    for uri in uris:
        results.append(uri)

    if len(results) > 0:
        print("Found: %s matches." % (len(results)))
        print()
        return {
            "matches": len(results),
            "result": results,
        }
    else:
        return {"matches": 0, "result": []}

    os.system('rm temp.txt')        