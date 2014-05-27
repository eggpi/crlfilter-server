#!/usr/bin/env python

import urlparse
import BaseHTTPServer

import crlfilter

class CRLFilterHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_GET(self):
        (_, _, _, _, query, _) = urlparse.urlparse(self.path)
        if query:
            version = urlparse.parse_qs(query)["v"][0]
            self.serve_diff_for_version(version)
        else:
            self.serve_latest_crlfilter()

    def serve_diff_for_version(self, version):
        self.send_response(200)

    def serve_latest_crlfilter(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()

        latest_crlfilter = self.get_latest_crlfilter()
        self.wfile.write(latest_crlfilter.tobytes())

    def get_latest_crlfilter(self):
        return crlfilter.build_crlfilter_from_crlcache(
                "../crlcache-1398468143.pkl", 1, 7)

if __name__ == '__main__':
    httpd = BaseHTTPServer.HTTPServer(("", 8001), CRLFilterHandler)
    httpd.serve_forever()
