import requests

import ssl

import socket

import nmap

import time

from typing import Dict, Callable


class ScannerModule:

    def __init__(self):

        self.modules = {

            'http_headers': self.verify_http_headers,

            'tls_certificate': self.verify_tls_certificate,

            'port_scan': self.verify_port_scan

        }

    

    def verify_http_headers(self, ip: str) -> Dict:

        """Check HTTP headers for security misconfigurations"""

        try:

            start_time = time.time()

            response = requests.get(f"http://{ip}", timeout=5)

            duration = time.time() - start_time

            

            headers = response.headers

            findings = []

            

            if 'Server' in headers:

                findings.append({"type": "header", "name": "Server", "value": headers['Server'], "risk": "low"})

            

            if 'X-Frame-Options' not in headers:

                findings.append({"type": "header", "name": "X-Frame-Options", "missing": True, "risk": "high"})

                

            if 'Strict-Transport-Security' not in headers:

                findings.append({"type": "header", "name": "Strict-Transport-Security", "missing": True, "risk": "medium"})

                

            return {

                "status": "success",

                "duration": duration,

                "findings": findings

            }

        except Exception as e:

            return {"status": "error", "message": str(e)}

    

    def verify_tls_certificate(self, ip: str) -> Dict:

        """Check TLS certificate for validity and vulnerabilities"""

        try:

            start_time = time.time()

            context = ssl.create_default_context()

            with socket.create_connection((ip, 443), timeout=5) as sock:

                with context.wrap_socket(sock, server_hostname=ip) as ssock:

                    cert = ssock.getpeercert()

            duration = time.time() - start_time

            

            if not cert:

                return {"status": "error", "message": "No certificate available"}

                

            findings = []

            expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')

            days_to_expiry = (expiry_date - datetime.now()).days

            if days_to_expiry < 30:

                findings.append({

                    "type": "certificate",

                    "name": "Expiry Date",

                    "value": expiry_date.strftime("%Y-%m-%d"),

                    "risk": "critical"

                })

                

            if 'TLS_RSA_WITH_AES_256_CBC_SHA' in cert.get('cipher_suite', ''):

                findings.append({

                    "type": "cipher",

                    "name": "Weak Cipher",

                    "value": "AES-256-CBC",

                    "risk": "high"

                })

                

            return {

                "status": "success",

                "duration": duration,

                "findings": findings

            }

        except Exception as e:

            return {"status": "error", "message": str(e)}

    

    def verify_port_scan(self, ip: str) -> Dict:

        """Scan open ports using nmap"""

        try:

            start_time = time.time()

            nm = nmap.PortScanner()

            nm.scan(ip, arguments='-p 1-1024 -T4 -sV')

            duration = time.time() - start_time

            

            ports = []

            for port in nm[ip].all_tcp():

                service = nm[ip]['tcp'][port].get('name', 'unknown')

                state = nm[ip]['tcp'][port].get('state', 'unknown')

                version = nm[ip]['tcp'][port].get('version', '')

                ports.append({

                    'number': port,

                    'service': service,

                    'state': state,

                    'version': version

                })

                

            return {

                "status": "success",

                "duration": duration,

                "ports": ports

            }

        except Exception as e:

            return {"status": "error", "message": str(e)}
