import requests

from chalicelib import definitions


def send_request(request, scheme):
    url = "{}://{}{}".format(scheme, request.headers.get("host"), request.path)

    req = requests.Request(
        request.method,
        url,
        params=request.params,
        data=request.data,
        headers=request.headers,
    )

    prepared_request = req.prepare()
    session = requests.Session()
    response = session.send(
        prepared_request, allow_redirects=False, verify=False,
    )  # proxies=definitions.PROXIES

    return response
