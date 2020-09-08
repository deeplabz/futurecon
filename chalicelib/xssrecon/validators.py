import requests

from chalicelib.definitions import SCAN_OPTIONS


def validate_scan_option(scan_option):
    return True if scan_option in SCAN_OPTIONS else False


def validate_request_option(string_request):
    return True if string_request is not None else False
