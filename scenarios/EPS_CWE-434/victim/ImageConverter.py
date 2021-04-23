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
import os
import subprocess

try:
    import http.server as server
except ImportError:
    # Handle Python 2.x
    import SimpleHTTPServer as server


class HTTPRequestHandler(server.SimpleHTTPRequestHandler):
    """Extend SimpleHTTPRequestHandler to handle PUT requests"""
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

        # run the file converter
        # pstoedit -f plot-svg image_0501.eps > evil.svg
        subprocess.Popen(["pstoedit", "-f", "plot-svg", filename, filename + ".svg"])

if __name__ == '__main__':
    server.test(HandlerClass=HTTPRequestHandler)
