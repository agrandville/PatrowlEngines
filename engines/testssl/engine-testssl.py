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
    res = {"page": "status"}

    try:
        res = engine.getstatus_scan(scan_id)
        return res
    except Exception as ex:
        app.logger.error(ex)
        res.update({
            "status": "error",
            "details": {
                "reason": "{}".format(ex)
            }
        })

        return jsonify(res)


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
    return engine.getfindings(scan_id)


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

    th = threading.Thread(
        target=_scan_thread,
        kwargs={
            "scan_id": scan_id,
            "asset": engine.scans[scan_id]["assets"],
            "asset_port": ""})
    th.start()
    engine.scans[scan_id]['threads'].append(th)

    engine.scans[scan_id]['status'] = "SCANNING"

    # Finish
    res.update({"status": "accepted"})
    return jsonify(res)


def _scan_thread(scan_id, asset, asset_port):
    app.logger.info("scan#" + scan_id + " starting ...")
    app.logger.debug("scan#" + scan_id + " assets " + json.dumps(engine.scans[scan_id]['assets']))

    output_dir = APP_BASE_DIR + "/results/"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    output_file = "{}/testssl_{}.tmp".format(
        output_dir,
        scan_id)

    if os.path.exists(output_file):
        # os.remove(output_file)
        app.logger.debug("scan#" + scan_id + " file removed " + output_file)

    cmd = APP_BIN_PATH + " -oJ " + output_file + " ";

    try:
        options = engine.scans[scan_id]['options']

        if type(options) == str:
            options = json.loads(options)

        if isTrue(options['check_protocols']):
            cmd += "-p "

        if isTrue(options['check_certificat']):
            cmd += "-S "

        if isTrue(options["check_vulnerabilities"]):
            cmd += "-U "

        if isTrue(options["check_ciphers"]):
            cmd += "-E "

    except Exception as ex:
        # engine.scans[scan_id]["state"] = "error"
        # { "reason": "options read failed {}".format(ex) }
        app.logger.debug("scan#" + scan_id + " options read failed " + str(ex))
        return

    cmd += asset[0]['value'];
    # cmd = "sleep 1"
    app.logger.debug("scan#" + scan_id + " starting... " + cmd)
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    returncode = p.poll()
    while returncode is None:
        app.logger.debug("scan#" + scan_id + " running...")
        time.sleep(5)
        returncode = p.poll()

    if returncode == 0:
        app.logger.debug("scan#" + scan_id + " parsing results...")

        try:
            # output_file = "/home/test/PatrowlEngines/engines/testssl/results/testssl_68.tmp"
            with open(output_file, 'r') as fd:
                json_data = json.loads(fd.read())

            _parse_results(json_data, engine.scans[scan_id])

        except Exception as ex:
            app.logger.error("scan#" + scan_id + " parse result failed " + str(ex))

    engine.scans[scan_id]['status'] = "FINISHED"


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


def _parse_results(json_output, scan):
    issue_id = 0
    findings = []
    scan_id = scan["scan_id"]

    # Check file
    # app.logger.info(json_output)

    # iterations over wanted items
    for key in TESTSSL_OUTPUT:

        # iterations over items find in response
        for result in json_output['scanResult'][0][key]:

            # find item
            item = FindItem(result["id"], TESTSSL_OUTPUT[key].keys())
            if item is not None:
                issue_id += 1
                new_finding = PatrowlEngineFinding(
                    issue_id=issue_id,
                    type="testssl_scan_{}".format(key),
                    title=TESTSSL_OUTPUT[key][item].format(result["finding"]),
                    description=TESTSSL_OUTPUT[key][item].format(result["finding"]),
                    solution="n/a",
                    severity="info",
                    confidence="firm",
                    raw=result["id"] + " " + result["finding"],
                    target_addrs={scan['assets'][0]['value']: {"datatype": scan['assets'][0]['datatype']}}
                )
                findings.append(new_finding)

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

    return True


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
