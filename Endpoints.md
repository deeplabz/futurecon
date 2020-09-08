## Endpoints

### GET - /api/

Response:
```json
{
    "status": "ok",
    "message": "Hey, welcome to the Futurecon API",
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