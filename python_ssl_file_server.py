import http.server
import ssl
import os
import io
from http import HTTPStatus
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone
import signal
import sys
import random
import string
import base64

class SimpleHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    username = ''
    password = ''
    
    def do_AUTHHEAD(self):
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header('WWW-Authenticate', 'Basic realm=\"Test\"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        auth_header = self.headers.get('Authorization')
        if self.is_authenticated(auth_header):
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"""
                <html>
                    <body>
                        <form enctype="multipart/form-data" method="post">
                            <input type="file" name="file" />
                            <input type="submit" value="Upload" />
                        </form>
                    </body>
                </html>
            """)
        else:
            self.do_AUTHHEAD()
            self.wfile.write(b"Unauthorized")

    def do_POST(self):
        auth_header = self.headers.get('Authorization')
        if not self.is_authenticated(auth_header):
            self.do_AUTHHEAD()
            self.wfile.write(b"Unauthorized")
            return

        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        boundary = self.headers['Content-Type'].split("boundary=")[1].encode()
        parts = post_data.split(boundary)
        for part in parts:
            if b'Content-Disposition' in part and b'name="file"' in part:
                filename = part.split(b'filename="')[1].split(b'"')[0].decode()
                file_data = part.split(b'\r\n\r\n')[1].rsplit(b'\r\n', 1)[0]
                with open(filename, 'wb') as output_file:
                    output_file.write(file_data)

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"File uploaded successfully.")

    def is_authenticated(self, auth_header):
        if auth_header is None:
            return False
        auth_type, credentials = auth_header.split(' ')
        decoded_credentials = base64.b64decode(credentials).decode()
        username, password = decoded_credentials.split(':')
        return username == self.username and password == self.password

def generate_self_signed_cert(cert_file, key_file):
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        print("Generating self-signed certificate...")
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        ])
        now = datetime.now(timezone.utc)
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now
        ).not_valid_after(
            now + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        ).sign(key, hashes.SHA256(), default_backend())

        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        with open(key_file, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

def generate_credentials():
    username = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    return username, password

def run(server_class=http.server.HTTPServer, handler_class=SimpleHTTPRequestHandler):
    server_address = ('', 8080)
    httpd = server_class(server_address, handler_class)

    cert_file = 'server.crt'
    key_file = 'server.key'

    # Generate self-signed certificate if it doesn't exist
    generate_self_signed_cert(cert_file, key_file)

    # Create SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)

    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    # Generate and set credentials
    username, password = generate_credentials()
    handler_class.username = username
    handler_class.password = password

    print(f"Username: {username}")
    print(f"Password: {password}")

    def signal_handler(sig, frame):
        print('Shutting down gracefully...')
        httpd.server_close()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    print("Starting server on https://localhost:8080...")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
