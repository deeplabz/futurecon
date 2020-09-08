import csv
import io
import json
import os
import random
import re
import sys
from collections import defaultdict
from optparse import OptionParser

from chalicelib import definitions

from .lib.evillib import def_headers, urlParser, waftoolsengine
from .manager import load_plugins


class WAFW00F(waftoolsengine):
    xsstring = '<script>alert("XSS");</script>'
    sqlistring = "UNION SELECT ALL FROM information_schema AND ' or SLEEP(5) or '"
    lfistring = "../../../../etc/passwd"
    rcestring = "/bin/cat /etc/passwd; ping 127.0.0.1; curl google.com"
    xxestring = '<!ENTITY xxe SYSTEM "file:///etc/shadow">]><pwn>&hack;</pwn>'

    def __init__(
        self,
        target="www.example.com",
        debuglevel=0,
        path="/",
        followredirect=True,
        extraheaders={},
        proxies=None,
    ):
        self.attackres = None
        waftoolsengine.__init__(
            self, target, debuglevel, path, proxies, followredirect, extraheaders
        )
        self.knowledge = dict(generic=dict(found=False, reason=""), wafname=list())

    def normalRequest(self):
        return self.Request()

    def customRequest(self, headers=None):
        return self.Request(headers=headers)

    def nonExistent(self):
        return self.Request(path=self.path + str(random.randrange(100, 999)) + ".html")

    def xssAttack(self):
        return self.Request(path=self.path, params={"s": self.xsstring})

    def xxeAttack(self):
        return self.Request(path=self.path, params={"s": self.xxestring})

    def lfiAttack(self):
        return self.Request(path=self.path + self.lfistring)

    def centralAttack(self):
        return self.Request(
            path=self.path,
            params={"a": self.xsstring, "b": self.sqlistring, "c": self.lfistring},
        )

    def sqliAttack(self):
        return self.Request(path=self.path, params={"s": self.sqlistring})

    def oscAttack(self):
        return self.Request(path=self.path, params={"s": self.rcestring})

    def performCheck(self, request_method):
        r = request_method()
        if r is None:
            raise RequestBlocked()
        return r

    # Most common attacks used to detect WAFs
    attcom = [xssAttack, sqliAttack, lfiAttack]
    attacks = [xssAttack, xxeAttack, lfiAttack, sqliAttack, oscAttack]

    def genericdetect(self):
        reason = ""
        reasons = [
            "Blocking is being done at connection/packet level.",
            "The server header is different when an attack is detected.",
            "The server returns a different response code when an attack string is used.",
            "It closed the connection for a normal request.",
            "The response was different when the request wasn't made from a browser.",
        ]
        try:
            # Testing for no user-agent response. Detects almost all WAFs out there.
            resp1 = self.performCheck(self.normalRequest)
            if "User-Agent" in self.headers:
                del self.headers[
                    "User-Agent"
                ]  # Deleting the user-agent key from object not dict.
            resp3 = self.customRequest(headers=def_headers)
            if resp1.status_code != resp3.status_code:
                print(
                    "Server returned a different response when request didn't contain the User-Agent header."
                )
                reason = reasons[4]
                reason += "\r\n"
                reason += 'Normal response code is "%s",' % resp1.status_code
                reason += (
                    ' while the response code to a modified request is "%s"'
                    % resp3.status_code
                )
                self.knowledge["generic"]["reason"] = reason
                self.knowledge["generic"]["found"] = True
                return True

            # Testing the status code upon sending a xss attack
            resp2 = self.performCheck(self.xssAttack)
            if resp1.status_code != resp2.status_code:
                print(
                    "Server returned a different response when a XSS attack vector was tried."
                )
                reason = reasons[2]
                reason += "\r\n"
                reason += 'Normal response code is "%s",' % resp1.status_code
                reason += (
                    ' while the response code to cross-site scripting attack is "%s"'
                    % resp2.status_code
                )
                self.knowledge["generic"]["reason"] = reason
                self.knowledge["generic"]["found"] = True
                return True

            # Testing the status code upon sending a lfi attack
            resp2 = self.performCheck(self.lfiAttack)
            if resp1.status_code != resp2.status_code:
                print(
                    "Server returned a different response when a directory traversal was attempted."
                )
                reason = reasons[2]
                reason += "\r\n"
                reason += 'Normal response code is "%s",' % resp1.status_code
                reason += (
                    ' while the response code to a file inclusion attack is "%s"'
                    % resp2.status_code
                )
                self.knowledge["generic"]["reason"] = reason
                self.knowledge["generic"]["found"] = True
                return True

            # Testing the status code upon sending a sqli attack
            resp2 = self.performCheck(self.sqliAttack)
            if resp1.status_code != resp2.status_code:
                print("Server returned a different response when a SQLi was attempted.")
                reason = reasons[2]
                reason += "\r\n"
                reason += 'Normal response code is "%s",' % resp1.status_code
                reason += (
                    ' while the response code to a SQL injection attack is "%s"'
                    % resp2.status_code
                )
                self.knowledge["generic"]["reason"] = reason
                self.knowledge["generic"]["found"] = True
                return True

            # Checking for the Server header after sending malicious requests
            response = self.attackres
            normalserver = resp1.headers.get("Server")
            attackresponse_server = response.headers.get("Server")
            if attackresponse_server:
                if attackresponse_server != normalserver:
                    print("Server header changed, WAF possibly detected")
                    print("Attack response: %s" % attackresponse_server)
                    print("Normal response: %s" % normalserver)
                    reason = reasons[1]
                    reason += (
                        '\r\nThe server header for a normal response is "%s",'
                        % normalserver
                    )
                    reason += (
                        ' while the server header a response to an attack is "%s",'
                        % attackresponse_server
                    )
                    self.knowledge["generic"]["reason"] = reason
                    self.knowledge["generic"]["found"] = True
                    return True

        # If at all request doesn't go, press F
        except RequestBlocked:
            self.knowledge["generic"]["reason"] = reasons[0]
            self.knowledge["generic"]["found"] = True
            return True
        return False

    def matchHeader(self, headermatch, attack=False):
        if attack:
            r = self.attackres
        else:
            r = rq
        if r is None:
            return
        header, match = headermatch
        headerval = r.headers.get(header)
        if headerval:
            # set-cookie can have multiple headers, python gives it to us
            # concatinated with a comma
            if header == "Set-Cookie":
                headervals = headerval.split(", ")
            else:
                headervals = [headerval]
            for headerval in headervals:
                if re.search(match, headerval, re.I):
                    return True
        return False

    def matchStatus(self, statuscode, attack=True):
        if attack:
            r = self.attackres
        else:
            r = rq
        if r is None:
            return
        if r.status_code == statuscode:
            return True
        return False

    def matchCookie(self, match, attack=False):
        return self.matchHeader(("Set-Cookie", match), attack=attack)

    def matchReason(self, reasoncode, attack=True):
        if attack:
            r = self.attackres
        else:
            r = rq
        if r is None:
            return
        # We may need to match multiline context in response body
        if str(r.reason) == reasoncode:
            return True
        return False

    def matchContent(self, regex, attack=True):
        if attack:
            r = self.attackres
        else:
            r = rq
        if r is None:
            return
        # We may need to match multiline context in response body
        if re.search(regex, r.text, re.I):
            return True
        return False

    wafdetections = dict()

    plugin_dict = load_plugins()
    result_dict = {}
    for plugin_module in plugin_dict.values():
        wafdetections[plugin_module.NAME] = plugin_module.is_waf
    # Check for prioritized ones first, then check those added externally
    checklist = definitions.WAF_SIGNATURES
    checklist += list(set(wafdetections.keys()) - set(checklist))

    def identwaf(self, findall=False):
        detected = list()
        try:
            self.attackres = self.performCheck(self.centralAttack)
        except RequestBlocked:
            return detected
        for wafvendor in self.checklist:
            print("Checking for %s" % wafvendor)
            if self.wafdetections[wafvendor](self):
                detected.append(wafvendor)
                if not findall:
                    break
        self.knowledge["wafname"] = detected
        return detected


def calclogginglevel(verbosity):
    default = 40  # errors are printed out
    level = default - (verbosity * 10)
    if level < 0:
        level = 0
    return level


def buildResultRecord(url, waf):
    result = {}
    result["url"] = url
    if waf:
        result["detected"] = True
        if waf == "generic":
            result["firewall"] = "Generic"
            result["manufacturer"] = "Unknown"
        else:
            result["firewall"] = waf.split("(")[0].strip()
            result["manufacturer"] = waf.split("(")[1].replace(")", "").strip()
    else:
        result["detected"] = False
        result["firewall"] = "None"
        result["manufacturer"] = "None"
    return result


def getTextResults(res=None):
    # leaving out some space for future possibilities of newer columns
    # newer columns can be added to this tuple below
    keys = "detected"
    res = [({key: ba[key] for key in ba if key not in keys}) for ba in res]
    rows = []
    for dk in res:
        p = [str(x) for _, x in dk.items()]
        rows.append(p)
    for m in rows:
        m[1] = "%s (%s)" % (m[1], m[2])
        m.pop()
    defgen = [(max([len(str(row[i])) for row in rows]) + 3) for i in range(len(rows[0]))]
    rwfmt = "".join(["{:>" + str(dank) + "}" for dank in defgen])
    textresults = []
    for row in rows:
        textresults.append(rwfmt.format(*row))
    return textresults


def getheaders(fn):
    headers = {}
    if not os.path.exists(fn):
        logging.getLogger("wafw00f").critical('Headers file "%s" does not exist!' % fn)
        return
    with io.open(fn, "r", encoding="utf-8") as f:
        for line in f.readlines():
            _t = line.split(":", 2)
            if len(_t) == 2:
                h, v = map(lambda x: x.strip(), _t)
                headers[h] = v
    return headers


class RequestBlocked(Exception):
    pass

def main(domains=[]):
    # '-v', '--verbose', 'Enable verbosity, multiple -v options increase verbosity', default=0
    # '-a', '--findall', 'Find all WAFs which match the signatures, do not stop testing on the first one'
    # '-r', '--noredirect', 'Do not follow redirections given by 3xx responses'
    # '-p', '--proxy', 'Use an HTTP proxy to perform requests, examples: http://hostname:8080, socks5://hostname:1080, http://user:pass@hostname:8080'
    targets = domains
    results = []
    for target in targets:
        if not target.startswith("http"):
            print(
                "The url %s should start with http:// or https:// .. fixing (might make this unusable)"
                % target
            )
            target = "https://" + target
        print("[*] Checking %s" % target)
        pret = urlParser(target)
        if pret is None:
            print("The url %s is not well formed" % target)

        (hostname, _, path, _, _) = pret
        print("starting wafw00f on %s" % target)
        proxies = dict()
        # if options.proxy:
        #     proxies = {
        #         "http": options.proxy,
        #         "https": options.proxy,
        #     }
        attacker = WAFW00F(
            target,
            debuglevel=0,
            path=path,
            followredirect=True,
            extraheaders={},
            proxies=None,
        )
        global rq
        rq = attacker.normalRequest()
        if rq is None:
            print("Site %s appears to be down" % hostname)
            continue
        findall = False
        waf = attacker.identwaf(findall)
        print("Identified WAF: %s" % waf)
        if len(waf) > 0:
            for i in waf:
                results.append(buildResultRecord(target, i))
            print("[+] The site %s is behind %s WAF." % (target, waf))
        if (findall) or len(waf) == 0:
            print("[+] Generic Detection results:")
            if attacker.genericdetect():
                print("Generic Detection: %s" % attacker.knowledge["generic"]["reason"])
                print(
                    "[*] The site %s seems to be behind a WAF or some sort of security solution"
                    % target
                )
                print("[~] Reason: %s" % attacker.knowledge["generic"]["reason"])
                results.append(buildResultRecord(target, "generic"))
            else:
                print("[-] No WAF detected by the generic detection")
                results.append(buildResultRecord(target, None))
    if len(results) > 0:
        print("Found: %s matches." % (len(results)))
        print()
        return {
            "numberrequests": attacker.requestnumber,
            "matches": len(results),
            "result": results,
        }
    else:
        return {"numberrequests": attacker.requestnumber, "matches": 0, "result": []}
