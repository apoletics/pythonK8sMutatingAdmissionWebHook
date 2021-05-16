#!/usr/bin/env python3
"""
Very simple HTTP server in python for logging requests
Usage::
    ./server.py [<port>]
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
import ssl
import json
import base64
import signal

class WebHookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
        post_data = self.rfile.read(content_length) # <--- Gets the data itself
        admissionReviewObject = json.loads(post_data.decode('utf-8'))
        reviewResponse = {}
        reviewResponse["uid"] = admissionReviewObject["request"]["uid"]
        reviewResponse["allowed"] = True
        reviewResponse["patchType"] = "JSONPatch"
        patch = []
        containers = admissionReviewObject["request"]["object"]["spec"]["containers"]
        index = 0
        for container in containers:
            path = "/spec/containers/"+str(index)+"/env"
            if "env" in container.keys():
                envValue = []
                found = False
                for runningEnv in container["env"]:
                    if (runningEnv["name"] == "TZ"):
                        found = True
                        if (runningEnv["value"] != "Asia/Hong_Kong" ):
                            runningEnv["value"] = "Asia/Hong_Kong"
                    envValue.append(runningEnv) 
                if (not found):
                    envValue.append({ "name": "TZ", "value": "Asia/Hong_Kong" })
            else:
                logging.info("Adding TZ to HKT")
                envValue = [ { "name": "TZ", "value": "Asia/Hong_Kong" } ] 
            envPatch = {}
            envPatch["op"] = "add"
            envPatch["path"] = path
            envPatch["value"] = envValue
            patch.append(envPatch)
            index += 1
        
        patchStr = json.dumps(patch)
        message_bytes = patchStr.encode('ascii')
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')

        reviewResponse["patch"] = base64_message

        admissionReviewObject["response"] =reviewResponse;

        logging.debug("RESPONSE ,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
                str(self.path), str(self.headers), json.dumps(admissionReviewObject))

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Content-length', str(len(json.dumps(admissionReviewObject).encode('utf-8')  )))
        self.end_headers()
        self.wfile.write(json.dumps(admissionReviewObject).encode('utf-8'))

webhook = None

def terminate(signal,frame):
    print("Stopping webhook at: %s" % datetime.now())
    webhook.server_close()
    sys.exit(0)


def run(server_class=HTTPServer, handler_class=WebHookHandler, port=8080):
    signal.signal(signal.SIGTERM, terminate)
    logging.basicConfig(level=logging.INFO)
    server_address = ('', port)
    webhook = server_class(server_address, handler_class)
    webhook.socket = ssl.wrap_socket (webhook.socket, certfile='/etc/certs/tls.crt',keyfile='/etc/certs/tls.key', server_side=True)
    logging.info('Starting webhook...\n')
    try:
        webhook.serve_forever()
    except KeyboardInterrupt:
        pass
    webhook.server_close()
    logging.info('Stopping webhook...\n')

if __name__ == '__main__':
    from sys import argv

    run()
