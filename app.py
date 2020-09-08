from chalice import Chalice

from chalicelib import definitions, utils
from chalicelib.xssrecon import scanner
from chalicelib.wafw00f import wafwoof
from chalicelib.parth import parthy
from chalicelib.waybackurls import waybackurls

app = Chalice(app_name=definitions.APP_NAME)


@app.route("/wafw00f", methods=["GET"])
def wafw00f():
    request_body = app.current_request.query_params
    domains_args = None
    domains = None

    if request_body:
        domains_args = request_body.get("domains")
        if domains_args:
            domains = domains_args.split(",")
    else:
        return {"error": "Make sure to send the domains parameter correctly"}

    try:
        result = wafwoof.main(domains=domains)

        return {
            "message": "wafw00f",
            "status": "ok",
            "matches": result["matches"],
            "result": result["result"],
            "wafs": definitions.WAF_SIGNATURES,
        }
    except:
        return {"error": "Error running wafw00f -"}

@app.route("/parth", methods=["GET"])
def parth():
    request_body = app.current_request.query_params
    domain_arg = None

    if request_body and request_body.get("domain"):
        domain_arg = request_body.get("domain")
    else:
        return {"error": "Make sure to send the domain parameter correctly"}

    try:
        parth = parthy.Parth(domain_arg)
        result = parth.main()

        return {
            "message": "parth",
            "status": "ok",
            "result": result["result"]
        }
    except:
        return {"error": "Error running parth -"}

@app.route("/scan", methods=["GET"])
def scan():
    request_body = app.current_request.query_params

    if request_body:
        scan_option_args = request_body.get("scan_option")
    else:
        return {"error": "Make sure to send all the parameters"}

    try:
        scan = scanner.Scanner(
            scan_option=scan_option_args,
            string_request=definitions.HTTP_REQUEST_EXAMPLE
        )

        validation = scan.validate()

        if not (validation["error"] is None):
            return validation["error"]

        return scan.scan()
    except Exception as e:
        return {"error": "Exception: #{}".format(e)}


@app.route("/waybackurls", methods=["GET"])
def waybackurls():
    from chalicelib.waybackurls import waybackurls
    request_body = app.current_request.query_params
    domains_args = None
    domains = None

    if request_body:
        domain = request_body.get("domain")
    else:
        return {"error": "Make sure to send the domains parameter correctly"}

    try:
        result = waybackurls.main(domain=domain)

        return {
            "message": "waybackurls",
            "status": "ok",
            "domain": domain,
            "matches": result["matches"],
            "result": result["result"],
        }
    except:
        return {"error": "Error running waybackurls -"}

@app.route("/")
def index():
    return {"status": "ok", "message": "Hey, welcome to the Futurecon API"}
