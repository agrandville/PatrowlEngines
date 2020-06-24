#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""TESTSSL.SH PatrOwl engine application."""

import datetime
import hashlib
import json
import os
import subprocess
import threading
import time
import re
from urllib.parse import urlparse
from pathlib import Path
from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngine
from PatrowlEnginesUtils.PatrowlEngine import PatrowlEngineFinding
from PatrowlEnginesUtils.PatrowlEngineExceptions import PatrowlEngineExceptions
from flask import Flask, request, jsonify

# from flask_cors import CORS

APP_DEBUG = False
APP_HOST = "0.0.0.0"
APP_PORT = 5017
APP_MAXSCANS = 3
APP_ENGINE_NAME = "testssl"
APP_BASE_DIR = os.path.dirname(os.path.realpath(__file__))
APP_BIN_PATH = APP_BASE_DIR + "/bin/testssl.sh"

TESTSSL_VULNERABILITIES_ID = {
    "heartbleed": "heartbleed {}",
    "CCS": "CCS {}",
    "ticketbleed": "ticketbleed {}",
    "ROBOT": "ROBOT {}",
    "secure_renego": "secure renegotation {}",
    "secure_client_renego": "client secure renegotation {}",
    "CRIME_TLS": "CRIME_TLS {}",
    "BREACH": "BREACH {}",
    "POODLE_SSL": "POODLE_SSL {}",
    "fallback_SCSV": "fallback_SCSV {}",
    "SWEET32": "SWEET32 {}",
    "FREAK": "FREAK {}",
    "DROWN": "DROWN {}",
    "DROWN_hint": "DROWN hint {}",
    "LOGJAM": "LOGJAM {}",
    "LOGJAM-common_primes": "LOGJAM common primes {}",
    "BEAST_CBC_TLS1": "BEAST CBC_TLS1 {}",
    "BEAST": "BEAST {}",
    "LUCKY13": "LUCKY13 {}",
    "RC4": "RC4 {}"
}

TESTSSL_PROTOCOLS_ID = {"SSLv2": "SSLv2 {}",
                        "SSLv3": "SSLv3 {}",
                        "TLS1": "TLSv1.0 {}",
                        "TLS1_1": "TLSv1.1 {}",
                        "TLS1_2": "TLSv1.2 {}",
                        "TLS1_3": "TLSv1.3 {}",
                        "ALPN_HTTP2": "ALPN_HTTP2 {}",
                        "ALPN": "ALPN {}"}

TESTSSL_CIPHER_ID = {"cipher-tls.*": "{}"}

TESTSSL_TLS_CERT_ID = {"cert_signatureAlgorithm{}": "Certificate{} signature algorithm {}",
                       "cert_keySize{}": "Certificate{} key size {}",
                       "cert_fingerprintSHA256{}": "Certificate{} fingerprint {}",
                       "cert_commonName{}": "Certificat{} CommonName {}",
                       "cert_caIssuers{}": "Certificat{} Issuer {}",
                       "cert_certificatePolicies_EV{}": "Certificat{} Extended Validation {}",
                       "OCSP_stapling{}": "Certificat{} OCSP stapling {}",
                       "certificate_transparency{}": "Certificat{} certificate transparency {}"

                       }
TESTSSL_TLS_SERVER_ID = {"cert_numbers": "Certificate(s) received {}",
                         "TLS_session_ticket": "Session ticket TTL {}"
                         }

TESTSSL_OUTPUT = {"protocols": TESTSSL_PROTOCOLS_ID,
                  "serverDefaults": TESTSSL_TLS_SERVER_ID,
                  "vulnerabilities": TESTSSL_VULNERABILITIES_ID,
                  "cipherTests": TESTSSL_CIPHER_ID}

app = Flask(__name__)
# CORS(app)
engine = PatrowlEngine(
    app=app,
    base_dir=APP_BASE_DIR,
    name=APP_ENGINE_NAME,
    max_scans=APP_MAXSCANS
)


@app.errorhandler(404)
def page_not_found(e):
    """Page not found."""
    return engine.page_not_found()


@app.errorhandler(PatrowlEngineExceptions)
def handle_invalid_usage(error):
    """Invalid request usage."""
    response = jsonify(error.to_dict())
    response.status_code = 404
    return response


@app.route('/')
def default():
    """Route by default."""
    return engine.default()


@app.route('/engines/testssl/')
def index():
    """Return index page."""
    return engine.index()


@app.route('/engines/testssl/liveness')
def liveness():
    """Return liveness page."""
    return engine.liveness()


@app.route('/engines/testssl/readiness')
def readiness():
    """Return readiness page."""
    return engine.readiness()


@app.route('/engines/testssl/test')
def test():
    """Return test page."""
    return engine.test()


@app.route('/engines/testssl/reloadconfig')
def reloadconfig():
    """Reload the configuration file."""
    return engine.reloadconfig()


@app.route('/engines/testssl/info')
def info():
    """Get info on running engine."""
    return engine.info()


@app.route('/engines/testssl/clean')
def clean():
    """Clean all scans."""
    return engine.clean()


@app.route('/engines/testssl/clean/<scan_id>')
def clean_scan(scan_id):
    """Clean scan identified by id."""
    return engine.clean_scan(scan_id)


@app.route('/engines/testssl/status')
def status():
    """Get status on engine and all scans."""
    return engine.getstatus()


@app.route('/engines/testssl/status/<scan_id>')
def status_scan(scan_id):
    """Get status on scan identified by id."""
    return engine.getstatus_scan(scan_id)

@app.route('/engines/testssl/stopscans')
def stop():
    """Stop all scans."""
    return engine.stop()


@app.route('/engines/testssl/stop/<scan_id>')
def stop_scan(scan_id):
    """Stop scan identified by id."""
    return engine.stop_scan(scan_id)


@app.route('/engines/testssl/getfindings/<scan_id>')
def getfindings(scan_id):
    """Get findings on finished scans."""
    res = {"page": "getfindings", "scan_id": scan_id}
    message = ""

    issues = []
    findings = []
    status = {"status": "SUCCESS"}

    summary = {
        "nb_issues": 0,
        "nb_info": 0,
        "nb_low": 0,
        "nb_medium": 0,
        "nb_high": 0,
        "engine_name": "testssl",
        "engine_version": "1"
    }

    # check if the scan is finished
    try:
        engine.getstatus_scan(scan_id)
        if engine.scans[scan_id]['status'] not in ["FINISHED", "ERROR"]:
            res.update({"status": engine.scans[scan_id]['status'], "reason": engine.scans[scan_id]['reason']})
            return jsonify(res)
    except Exception as ex:
        res.update({"status": "ERROR",
            "reason": ex.__str__()})
        return jsonify(res)

    # parse result files
    for asset in engine.scans[scan_id]['assets']:
        try:
            if asset["status"] == "ERROR":
                raise PatrowlEngineExceptions(1003,asset["reason"])
            else:
                output_file = asset['output_file']
                #output_file = "/home/test/PatrowlEngines/engines/testssl/results/testssl_123.tmp"
                with open(output_file, 'r') as fd:
                    json_data = json.loads(fd.read())

                _parse_results(status, findings, summary, json_data, scan_id, asset)
        except Exception as ex:
            message = "scan#{} asset#{} failed  {}".format(scan_id, asset['id'], ex.__str__())
            status = { "status": "error", "reason": message, "finished_at": int(time.time() * 1000) }
            engine.scans[scan_id].update(status)
            app.logger.error(message)
            res.update(status)
            return jsonify(res)

    scan = {
        "scan_id": scan_id,
        "assets": engine.scans[scan_id]['assets'],
        "options": engine.scans[scan_id]['options'],
        "started_at": engine.scans[scan_id]['started_at'],
        "finished_at": engine.scans[scan_id]['finished_at']
    }

    json_findings = []
    a = ""
    for finding in findings:
        json_findings.append(finding._PatrowlEngineFinding__to_dict())

    # Store the findings in a file
    output_dir = Path(APP_BASE_DIR)
    output_dir = Path(output_dir / "results")
    output_file = output_dir / "testssl_{}.json".format(
        scan_id
    )

    with open(output_file, 'w') as report_file:
        json.dump({
            "scan": scan,
            "summary": summary,
            "issues": issues
        }, report_file)

    # remove the scan from the active scan list
    # clean_scan(scan_id)

    res.update(status)
    res.update({"scan": scan, "summary": summary, "issues": json_findings})
    return res


@app.route('/engines/testssl/getreport/<scan_id>')
def getreport(scan_id):
    """Get report on finished scans."""
    return engine.getreport(scan_id)


@app.route('/engines/testssl/startscan', methods=['POST'])
def startscan():
    """Start a new scan."""
    # Check params and prepare the PatrowlEngineScan
    res = engine.init_scan(request.data)
    if "status" in res.keys() and res["status"] != "INIT":
        return jsonify(res)


    scan_id = res["details"]["scan_id"]
    engine.scans[scan_id].update({"results": []})

    for asset in engine.scans[scan_id]["assets"]:
        th = threading.Thread(
            target=_scan_thread,
            kwargs={
                "scan_id": scan_id,
                "asset": asset})
        th.start()
        engine.scans[scan_id]['threads'].append(th)


    engine.scans[scan_id]['status'] = "SCANNING"

    # Finish
    res.update({"status": "accepted"})
    return jsonify(res)


def _scan_thread(scan_id, asset):
    asset_id = asset["id"]
    asset_pos = engine.scans[scan_id]["assets"].index(asset)

    app.logger.info("scan#{} start scanning asset#{} {}...".format(scan_id, asset["id"],asset["value"]))

    output_dir = Path(APP_BASE_DIR)
    output_dir = Path(output_dir / "results")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    output_file = output_dir / "testssl_{}-{}.tmp".format(
        317, #scan_id,
        asset_id)

    asset.update({"output_file": str(output_file) })
    engine.scans[scan_id]["assets"][asset_pos].update(asset)

    if os.path.exists(output_file):
        # os.remove(output_file)
        app.logger.info("scan#{} file removed {}.".format(scan_id, output_file))

    cmd = APP_BIN_PATH + " -oJ {} ".format(output_file)

    try:
        options = engine.scans[scan_id]['options']

        if type(options) == str:
            options = json.loads(options)

        for option in options.keys():
            if option in 'check_protocols' and isTrue(options['check_protocols']):
                cmd += "-p "
            elif option in 'check_certificat' and isTrue(options['check_certificat']):
                cmd += "-S "
            elif option in 'check_vulnerabilities' and isTrue(options['check_vulnerabilities']):
                cmd += "-U "
            elif option in 'check_ciphers' and isTrue(options['check_ciphers']):
                cmd += "-E "
            else:
                raise Exception("unknown option",option)

    except Exception as ex:
        message = "error {}".format(ex.__str__())
        asset.update({"status": "ERROR", "reason": message, "finished_at": int(time.time() * 1000) })
        engine.scans[scan_id]["assets"][asset_pos].update(asset)
        app.logger.error(message)
        return

    cmd += asset['value']
    cmd = "sleep 1"
    app.logger.debug("scan#{} asset#{} starting {}... ".format(scan_id, asset_id,cmd))
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # wait process exit
    returncode = p.poll()
    while returncode is None:
        app.logger.debug("scan#{} asset#{} is running...".format( scan_id, asset_id ))
        time.sleep(5)
        returncode = p.poll()

    # check return code
    if returncode == 0:
        app.logger.debug("scan#{} asset#{} finished...".format( scan_id, asset_id ))
    else:
        message = "scan#{} asset#{} testssl exit code {}".format(scan_id, asset_id, returncode)
        asset.update({"status": "ERROR", "reason": message, "finished_at": int(time.time() * 1000) })
        engine.scans[scan_id]["assets"][asset_pos].update(asset)
        app.logger.error(message)
        return

    asset.update({"status": "FINISHED", "finished_at": int(time.time() * 1000) })
    engine.scans[scan_id]["assets"][asset_pos].update(asset)


def FindItem(key, items):
    for item in items:
        # item is a string
        if key == item:
            return key
        try:
            # item maybe a regex
            p = re.compile(item)
            if p.match(key):
                return item
        except Exception as ex:
            app.logger.error(key + " regex failed " + str(ex))

    return None

def _parse_protocols(status, findings, summary, scan_id, asset, data):
    # {
    #   "id"           : "SSLv2",
    #   "severity"     : "OK",
    #   "finding"      : "not offered"
    # }
    #
    try:
        for entry in data:
            new_finding = PatrowlEngineFinding(
                issue_id=len(findings),
                type="testssl_scan_protocols",
                title="{} {}".format(entry["id"],entry['finding']),
                description="{} {}".format(entry["id"],entry['finding']),
                solution="n/a",
                severity="info",
                confidence="firm",
                raw=entry,
                target_addrs=[asset["value"]]
            )
            findings.append(new_finding)
    except Exception as ex:
        status.update({"status": "ERROR", "reason": "_parse_protocols failed {}".format(ex.__str__())})
        return False

    return True

def _parse_results(status, findings, summary, json_data, scan_id, asset):

    message = ""
    nb_vulns = {
        "info": 0,
        "low": 0,
        "medium": 0,
        "high": 0
    }


    # iterations over items in response
    ret = True
    for result in json_data['scanResult'][0]:
        if result == "protocols":
            ret = _parse_protocols(status, findings, summary,
                                   scan_id, asset,
                                   json_data['scanResult'][0]['protocols'])
        elif result == "scanResult":
                print(result)

        if not ret:
            break

        # find item
        # item = FindItem(result["id"], TESTSSL_OUTPUT[key].keys())
        if False:
            #if item is not None:
            issue_id += 1


            # iterations over certificats
            if result["id"] == 'cert_numbers':
                for current_certificate in range(1, 1 + int(format(result["finding"]))):
                    for key_id in TESTSSL_TLS_CERT_ID.keys():
                        if int(format(result["finding"])) == 1:
                            search_id = key_id.format("")
                            cert_id = ""
                        else:
                            cert_id = " <cert#" + str(current_certificate) + ">"
                            search_id = key_id.format(cert_id)

                        for certificats_attributs in json_output['scanResult'][0][key]:
                            if certificats_attributs['id'] == search_id:
                                issue_id += 1
                                new_finding = PatrowlEngineFinding(
                                    issue_id=issue_id,
                                    type="testssl_scan_{}".format(key),
                                    title=TESTSSL_TLS_CERT_ID[key_id].format(cert_id,
                                                                             certificats_attributs['finding']),
                                    description=TESTSSL_TLS_CERT_ID[key_id].format(cert_id, certificats_attributs[
                                        'finding']),
                                    solution="n/a",
                                    severity="info",
                                    confidence="firm",
                                    raw=certificats_attributs["id"] + " " + certificats_attributs["finding"],
                                    target_addrs={
                                        scan['assets'][0]['value']: {"datatype": scan['assets'][0]['datatype']}}
                                )
                                findings.append(new_finding)



    # Write results under mutex
    scan_lock = threading.RLock()
    with scan_lock:
        engine.scans[scan_id]["findings"] += findings





def isTrue(v):
    if isinstance(v, bool):
        return v
    return v.lower() in ("true", "1")


@app.before_first_request
def main():
    """First function called."""
    if not os.path.exists(APP_BASE_DIR + "/results"):
        os.makedirs(APP_BASE_DIR + "/results")
    engine._loadconfig()

    # Check if sslscan is available
    # if not os.path.isfile(engine.options["bin_path"]):
    #    sys.exit(-1)


if __name__ == '__main__':
    engine.run_app(app_debug=APP_DEBUG, app_host=APP_HOST, app_port=APP_PORT)
