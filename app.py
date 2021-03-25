import os

from chalice import Chalice

from chalicelib import definitions, utils

#### Importing tools -
from chalicelib.xssrecon import scanner
from chalicelib.wafw00f import wafwoof
from chalicelib.parth import parthy
from chalicelib.waybackurls import waybackurls

### Importing subdomain discovery tools -
from chalicelib.assetfinder import assetfinder
from chalicelib.subfinder import subfinder
from chalicelib.findomain import findomain
from chalicelib.amass import amass
from chalicelib.github_subdomains import github_subdomains

app = Chalice(app_name=definitions.APP_NAME)


### ROUTES -

## Subdomain Discovery -

# Assetfinder - Find domains and subdomains related to a given domain
@app.route("/assetfinder", methods=["GET"])
def assetfinder_call():
    request_body = app.current_request.query_params
    domains_args = None

    if request_body:
        domains_args = request_body.get("domains")
        if domains_args:
            domains = domains_args.split(",")
    else:
        return {"error": "Make sure to send the domains parameter correctly"}

    try:
        result = assetfinder.main(domains=domains)
        return {
            "message": "assetfinder",
            "status": "ok",
            "matches": result["matches"],
            "result": result["result"],
        }
    except:
        return {"error": "Error running assetfinder -"}

# Subfinder -
@app.route("/subfinder", methods=["GET"])
def subfinder_call():
    request_body = app.current_request.query_params
    domains_args = None

    if request_body:
        domains_args = request_body.get("domains")
        if domains_args:
            domains = domains_args.split(",")
    else:
        return {"error": "Make sure to send the domains parameter correctly"}

    try:
        result = subfinder.main(domains=domains)
        return {
            "message": "subfinder",
            "status": "ok",
            "matches": result["matches"],
            "result": result["result"],
        }
    except:
        return {"error": "Error running subfinder -"}

# Findomain -
@app.route("/findomain", methods=["GET"])
def findomain_call():
    request_body = app.current_request.query_params
    domains_args = None

    if request_body:
        domains_args = request_body.get("domains")
        if domains_args:
            domains = domains_args.split(",")
    else:
        return {"error": "Make sure to send the domains parameter correctly"}

    try:
        result = findomain.main(domains=domains)
        return {
            "message": "findomain",
            "status": "ok",
            "matches": result["matches"],
            "result": result["result"],
        }
    except:
        return {"error": "Error running findomain -"}

# Amass -
@app.route("/amass", methods=["GET"])
def amass_call():
    request_body = app.current_request.query_params
    domains_args = None

    if request_body:
        domains_args = request_body.get("domains")
        if domains_args:
            domains = domains_args.split(",")
    else:
        return {"error": "Make sure to send the domains parameter correctly"}

    try:
        result = amass.main(domains=domains)
        return {
            "message": "amass",
            "status": "ok",
            "matches": result["matches"],
            "result": result["result"],
        }
    except:
        return {"error": "Error running amass -"}

# Github Subdomains -
@app.route("/github-subdomains", methods=["GET"])
def github_subdomains_call():
    request_body = app.current_request.query_params
    domains_args = None

    if request_body:
        domains_args = request_body.get("domains")
        tokens = request_body.get("tokens")
        if domains_args:
            domains = domains_args.split(",")
    else:
        return {"error": "Make sure to send the domains parameter and tokens parameter correctly"}

    try:
        result = github_subdomains.main(domains=domains, tokens=tokens)
        return {
            "message": "github-subdomains",
            "status": "ok",
            "matches": result["matches"],
            "result": result["result"],
        }
    except:
        return {"error": "Error running github-subdomains -"}

# WAFW00F - Fingerprint Web Application Firewall (WAF).
@app.route("/wafw00f", methods=["GET"])
def wafw00f_call():
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

# Parth - Heuristic Vulnerable Parameter Scanner
@app.route("/parth", methods=["GET"])
def parth_call():
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
def scan_call():
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
def waybackurls_call():
    request_body = app.current_request.query_params
    domains_args = None

    if request_body:
        domains_args = request_body.get("domains")
        if domains_args:
            domains = domains_args.split(",")
    else:
        return {"error": "Make sure to send the domains parameter correctly"}

    print(domains)

    try:
        result = waybackurls.main(domains=domains)
        return {
            "message": "waybackurls",
            "status": "ok",
            "matches": result["matches"],
            "result": result["result"],
        }
    except:
        return {"error": "Error running waybackurls -"}


@app.route("/")
def index():
    return {"status": "ok", "message": "Hey, welcome to the Futurecon API"}
