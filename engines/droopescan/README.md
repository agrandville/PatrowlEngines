# Description
PatrOwl Droopscan engine

# Pre-requisites (must be installed before)
- Python 3 + pip + virtualenv

# Install notes
## With Docker
- Build image
```
docker build --force-rm --tag patrowl-droopescan .
```
 - Run container
 ```
 docker run --rm -p 5021:5021 patrowl-droopescan
 ```

## From sources
- Install python packages on system (use virtualenv)
```
cd PatrowlEngines/engines/droopscan
virtualenv env
source env/bin/activate
pip3 install -r requirements.txt
mkdir logs tmp results
```
- Create a configuration file (see droopscan.json.sample) named 'droopscan.json'

- Start the engine (require sudo/root access):
```
sudo env/bin/python engine-droopscan.py [--port 5021] [--host 0.0.0.0] [--debug]
```
> Note the use of `env/bin/python` allowing the reference of the python modules within the virtualenv

- or use Gunicorn (don't forget the `--preload` option if you use multiple workers!!):
sudo gunicorn engine-droopscan:app -b :5021 --access-logfile - --workers=4 -k gevent --preload

## Testing URLs
http://0.0.0.0:5021/engines/droopscan/test
http://0.0.0.0:5021/engines/droopscan/status
http://0.0.0.0:5021/engines/droopscan/info

## Testing script
```
import json, requests, time  

print("TEST CASE: test_scan_droopscan")
post_data = {
    "assets": [{
        "id": 5,
        "value": "$WORDPRESS_WEBSITE_URL",
        "criticity": "low",
        "datatype": "url"
    }],
    "options": {
        "scan_wordpress": 1
    },
    "scan_id": 556
}
r = requests.post(url='http://0.0.0.0:5021/engines/droopscan/startscan',
           data=json.dumps(post_data),
           headers = {'Content-type': 'application/json', 'Accept': 'application/json'})
```

## Pro functionnalities
- Support for multiple hosts
- Vulnerability finding and processing

