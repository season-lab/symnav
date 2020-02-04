from http.server import HTTPServer, CGIHTTPRequestHandler
import webbrowser
import os
import sys

#web_dir = os.path.join(os.path.dirname(__file__),"")
#os.chdir(web_dir)

port = 1234
host_name = "localhost"


httpd = HTTPServer((host_name, port), CGIHTTPRequestHandler)
print("server started, to quit press <ctrl-c>")
webbrowser.open_new_tab('http://localhost:' + str(port) + '')
httpd.serve_forever()

