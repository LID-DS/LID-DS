#!/usr/bin/env python

"""
from : https://f-o.org.uk/2017/receiving-files-over-http-with-python.html
edited by Martin Grimmer

Extend Python's built in HTTP server to save files

curl or wget can be used to send files with options similar to the following

  curl -X PUT --upload-file somefile.txt http://localhost:8000
  wget -O- --method=PUT --body-file=somefile.txt http://localhost:8000/somefile.txt

__Note__: curl automatically appends the filename onto the end of the URL so
the path can be omitted.

"""
import http.server as server
import os
import subprocess


class HTTPRequestHandler(server.SimpleHTTPRequestHandler):
    """Extend SimpleHTTPRequestHandler to handle PUT requests"""

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/txt')
        self.end_headers()
        reply_body = "READY\n"
        self.wfile.write(reply_body.encode('utf-8'))
        self.wfile.close();


    def do_PUT(self):
        """Save a file following a HTTP PUT request"""
        filename = os.path.basename(self.path)
        # Don't overwrite files
        if os.path.exists(filename):
            self.send_response(409, 'Conflict')
            self.end_headers()
            reply_body = '"%s" already exists\n' % filename
            self.wfile.write(reply_body.encode('utf-8'))
            return

        file_length = int(self.headers['Content-Length'])
        with open(filename, 'wb') as output_file:
            output_file.write(self.rfile.read(file_length))
        self.send_response(201, 'Created')
        self.end_headers()
        reply_body = 'Saved "%s"\n' % filename
        self.wfile.write(reply_body.encode('utf-8'))
        # run the java unpacker
        subprocess.Popen(["java", "-cp", "../zipslip-1.0.0.jar", "com.itsec.leipzig.zipslip.Unpack", filename])


if __name__ == '__main__':
    print("Victin started...")
    server.test(HandlerClass=HTTPRequestHandler)
