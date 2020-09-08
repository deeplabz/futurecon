
<div align="center">

[![Python 3.8](https://img.shields.io/badge/python-3.8-00acd2.svg)](https://www.python.org/downloads/release/python-380/)

</div>

<h3 align="center">
    :mag: Monitoring Domains :mag:
</h3>

### Install dependencies

- Only needs this step if you started without the use of Gitpod:
```
pip3 install -r requirements.txt
```

### One time configure:
- Required to configure your keys to amazon deploy:
```
pip3 install awscli
aws configure
pre-commit install
```

### Code Quality
```
flake8
isort
black
pre-commit run --all-files
```

### Run
- Local:
```
chalice local
```

- AWS:
```
chalice deploy
chalice deploy --stage prod
```

### Delete
```
chalice delete --stage dev
chalice delete --stage prod
```

### Debug
- Local:
```
import pdb; pdb.set_trace()
```

- AWS:
```
chalice logs
```