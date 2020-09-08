class RawHTTP:
    def __init__(self, request: object):
        self.rawRequest = self.makeRequest(request)

    def makeRequest(self, request: object) -> str:
        request.http_version = "HTTP/1.1"
        try:
            rawRequest = ""
            rawRequest += (
                str(request.method)
                + " "
                + str(request.path)
                + " "
                + str(request.http_version)
            )
            for k, v in request.headers.items():
                rawRequest += "\n"
                rawRequest += str(k) + ": " + str(v)

            if request.data:
                rawRequest += "\n\n"
                for data in request.data:
                    rawRequest += str(data) + "=" + str(request.data[data]) + "&"

            return rawRequest
        except Exception as e:
            raise Exception(e)
