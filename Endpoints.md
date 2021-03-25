## Endpoints

### GET - /api/

Response:
```json
{
    "status": "ok",
    "message": "Hey, welcome to the Futurecon API",
}
```

### GET - /assetfinder?domains=domain.com,domain2.com

Response:
```json
{
    "message": "assetfinder",
    "status": "ok",
    "matches": "<digit>",
    "result": [
        "subdomain",
    ],
}
```

### GET - /subfinder?domains=domain.com,domain2.com

Response:
```json
{
    "message": "subfinder",
    "status": "ok",
    "matches": "<digit>",
    "result": [
        "subdomain",
    ],
}
```

### GET - /findomain?domains=domain.com,domain2.com

Response:
```json
{
    "message": "findomain",
    "status": "ok",
    "matches": "<digit>",
    "result": [
        "subdomain",
    ],
}
```

### GET - /amass?domains=domain.com,domain2.com

Response:
```json
{
    "message": "amass",
    "status": "ok",
    "matches": "<digit>",
    "result": [
        "subdomain",
    ],
}
```

### GET - /github-subdomains?domains=domain.com,domain2.com&tokens=TOKEN1,TOKEN2

Response:
```json
{
    "message": "github-subdomains",
    "status": "ok",
    "matches": "<digit>",
    "result": [
        "subdomain",
    ],
}
```

### GET - /wafw00f?domains=https://www.pichau.com.br,https://www.fastshop.com.br

Response:
```json
{
    "status": "ok",
    "message": "wafw00f",
    "matches": "<digit>",
    "result": [{
        "url": <domain>,
        "detected": <bool>,
        "firewall": <name>,
    }],
    "wafs": [<waf>]
}
```

### GET - /waybackurls?domain=pichau.com.br

Response:
```json
{
    "message": "waybackurls",
    "status": "ok",
    "matches": "<digit>",
    "result": [{
        "url": <domain>,
    }],
}
```

### GET - /parth?domain=pichau.com.br

Response:
```json
{
    "message": "parth",
    "status": "ok",
    "result": [{
        "url": <url>,
        "issues": <issues>,
        "location": <location>,
        "data": <data>,
    }],
}
```

### GET - /api/scan?scan_option=all

Response:
```json
{
    "message": "No XSS found!",
}

or

{
    "message": "<Raw http request string>",
}
```

Scan Option:

    --all = Find everything