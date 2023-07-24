import http.server
import os


class LogServer(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/metrics':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            logs = self.get_logs()
            self.wfile.write(logs.encode())
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write('Not Found'.encode())

    def get_logs(self):
        log_files = ['connections.log',
                     'packets.log', 'err.log']
        logs = []
        for file in log_files:
            file_path = os.path.join(os.path.dirname(__file__), 'data', file)
            print(file_path)
            try:
                with open(file_path, 'r') as f:
                    logs.append(f.read())
            except FileNotFoundError:
                logs.append(f'File {file} not found.\n')
        return '\n'.join(logs)


if __name__ == '__main__':
    host = 'localhost'
    port = 41420
    server_address = (host, port)

    httpd = http.server.HTTPServer(server_address, LogServer)
    print(f'Starting log server on {host}:{port}...')
    httpd.serve_forever()
