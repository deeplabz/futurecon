import copy
import re

import requests
from lxml import html

from chalicelib import (
    definitions,
    utils,
)

from chalicelib.xssrecon import (
    context_analyzer,
    create_insertions,
    payload_generator,
    raw_http,
    request_parser,
    validators,
)


class Scanner:
    def __init__(self, scan_option, string_request):
        self.scan_option = scan_option
        self.string_request = string_request
        self.vulnerables = []

    def validate(self):
        if not validators.validate_scan_option(self.scan_option):
            return {"error": "Invalid scan option"}
        if not validators.validate_request_option(self.string_request):
            return {"error": "Invalid request option"}
        else:
            return {"error": None}

    def scan(self):
        try:
            parser = request_parser.RequestParser(self.string_request)
            i_p = create_insertions.GetInsertionPoints(parser.request)
            for request in i_p.requests:
                response = utils.send_request(request, "http")
                if definitions.PAYLOAD_IDENTIFICATION in response.text:
                    print("probe reflection found in " + request.insertion)
                    contexts = context_analyzer.ContextAnalyzer.get_contexts(
                        response.text, definitions.PAYLOAD_IDENTIFICATION
                    )
                    for context in contexts["contexts"]:
                        payloads = payload_generator.payload_generator(context["type"])
                        for payload in payloads:
                            dup = copy.deepcopy(request)
                            dup.replace(
                                definitions.PAYLOAD_IDENTIFICATION, payload["payload"]
                            )
                            response = utils.send_request(dup, "http")
                            page_html_tree = html.fromstring(response.text)
                            count = page_html_tree.xpath(payload["find"])
                            if len(count):
                                print("VULNERABLE TO XSS")
                                http = raw_http.RawHTTP(dup)
                                print(http.rawRequest)
                                self.vulnerables.append(str(http.rawRequest))

            if len(self.vulnerables) > 0:
                return {"message": str(self.vulnerables)}
            else:
                return {"message": "No XSS found!"}
        except Exception as e:
            return {"error": "Exception: #{}".format(e)}
