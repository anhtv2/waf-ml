#!/usr/bin/env python3
# encoding: utf-8

import os
import sys
import asyncio
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import sys
from urllib import parse

import time
import pickle

def get1Grams(payload_obj):
    '''
    Ví dụ: input - payload: "<script>"
             output- ["<","s","c","r","i","p","t",">"]
    '''
    payload = str(payload_obj)
    ngrams = []
    for i in range(0,len(payload)-1):
        ngrams.append(payload[i:i+1])
    return ngrams

def get2Grams(payload_obj):
    '''
    Ví dụ: input - payload: "<script>"
             output- ["<s","sc","cr","ri","ip","pt","t>"]
    '''
    payload = str(payload_obj)
    ngrams = []
    for i in range(0,len(payload)-2):
        ngrams.append(payload[i:i+2])
    return ngrams

classifier_results = pickle.load( open( "trained_classifiers.p", "rb" ) )
classifier = (classifier_results['model'].iloc[0])


def check_vuln(inputs):
    return True if classifier.predict([inputs]).sum() > 0 else False

def check_http_vuln(inputs):
    inputs = inputs.split(b'\r\n')[0]
    # Get url path only
    url = inputs.split(b' ')[1]
    
    params = parse.parse_qs(parse.urlparse(url).query)
    for key in params:
        if check_vuln(params[key][0]):
            print(f"Vuln: {params[key][0]}")
            return True

class ForwardedConnection(asyncio.Protocol):
    def __init__(self, peer):
        self.peer = peer
        self.transport = None
        self.buff = list()
        self.id = None

    def connection_made(self, transport):
        self.transport = transport
        if len(self.buff) > 0:
            self.transport.writelines(self.buff)
            self.buff = list()

    def data_received(self, data):
        print("\r\n[INFO] Response [id: %s] \r\n" % self.id)
        # try:
        #     print(str(data))
        # except:
        #     pass

        self.peer.write(data)

    def connection_lost(self, exc):
        self.peer.close()


# an instance of PortForwarder will be created for each client connection.
class PortForwarder(asyncio.Protocol):
    def __init__(self, dsthost, dstport):
        self.dsthost = dsthost
        self.dstport = dstport

    def connection_made(self, transport):
        self.transport = transport
        loop = asyncio.get_event_loop()
        self.fcon = ForwardedConnection(self.transport)
        asyncio.ensure_future(
            loop.create_connection(lambda: self.fcon, self.dsthost, self.dstport)
        )

    def data_received(self, data):
        id = time.time()
        print(
            "\r\n[INFO] Request from %s:%s [id: %s]\r\n"
            % (
                self.transport.get_extra_info("socket").getpeername()[0],
                self.transport.get_extra_info("socket").getpeername()[1],
                id,
            )
        )

        if check_http_vuln(data):
            print("[INFO] Detected Malicious Request")
            try: 
                print(str(data))
            except:
                pass
            self.transport.close()

        self.fcon.id = id
        if self.fcon.transport is None:
            self.fcon.buff.append(data)
        else:
            self.fcon.transport.write(data)

    def connection_lost(self, exc):
        if not self.fcon.transport is None:
            self.fcon.transport.close()


def main():
    remote_port = int(os.getenv("REMOTE_PORT", 80))
    chall_name = os.getenv("SERVICE_NAME", "unknown")
    loop = asyncio.get_event_loop()
    server = loop.run_until_complete(
        loop.create_server(
            lambda: PortForwarder(chall_name, remote_port), "0.0.0.0", 9999
        )
    )
    print("Forwarding localhost:%s <-> %s:%s ..." % (9999, chall_name, remote_port))
    try:
        loop.run_until_complete(server.wait_closed())
    except KeyboardInterrupt:
        sys.stderr.flush()
        print("\nStopped\n")


if __name__ == "__main__":
    main()
