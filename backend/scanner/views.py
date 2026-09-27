import re
import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

class ScanCodeView(APIView):
    def post(self, request):
        payload = request.data.get('payload', '')
        scan_type = request.data.get('type', 'text')  # 'text' or 'url'
        findings = []

        if scan_type == 'url':
            url = payload.strip()
            if not url.startswith(('http://', 'https://')):
                return Response({"error": "Invalid URL scheme. Must start with http:// or https://"}, 
                                status=status.HTTP_400_BAD_REQUEST)

            # Check 1: Insecure HTTP Protocol
            if url.startswith('http://'):
                findings.append({
                    "vulnerability": "Insecure Protocol (Cleartext HTTP)",
                    "match": url,
                    "severity": "HIGH"
                })

            # Check 2: Active Security Header Inspection
            try:
                resp = requests.get(url, timeout=5, headers={"User-Agent": "DevSecOps-Scanner/1.0"})
                headers = resp.headers

                security_headers = [
                    ("Content-Security-Policy", "Missing CSP (Cross-Site Scripting risk)", "MEDIUM"),
                    ("Strict-Transport-Security", "Missing HSTS (Man-in-the-Middle risk)", "MEDIUM"),
                    ("X-Frame-Options", "Missing X-Frame-Options (Clickjacking risk)", "LOW"),
                    ("X-Content-Type-Options", "Missing X-Content-Type-Options (MIME sniffing risk)", "LOW")
                ]

                for header, desc, sev in security_headers:
                    if header not in headers:
                        findings.append({
                            "vulnerability": f"{header} - {desc}",
                            "match": f"Header '{header}' not present",
                            "severity": sev
                        })

            except requests.RequestException as e:
                return Response({"error": f"Failed to connect to URL: {str(e)}"}, 
                                status=status.HTTP_400_BAD_REQUEST)

        else:
            # Code / Text Regex Scans
            rules = {
                "AWS Access Key": r"AKIA[0-9A-Z]{16}",
                "Generic Secret/Token": r"(?i)(secret|token|password)[\s=:>]+['\"]([^'\"]{8,})['\"]"
            }
            for risk, pattern in rules.items():
                matches = re.finditer(pattern, payload)
                for match in matches:
                    findings.append({
                        "vulnerability": risk,
                        "match": match.group(0),
                        "severity": "HIGH"
                    })

        return Response({
            "status": "Scan complete",
            "target": payload,
            "findings_count": len(findings),
            "findings": findings
        }, status=status.HTTP_200_OK)