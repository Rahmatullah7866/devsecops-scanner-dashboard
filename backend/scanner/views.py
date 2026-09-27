import re
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

class ScanCodeView(APIView):
    def post(self, request):
        target_text = request.data.get('payload', '')
        
        # Simple Regex rules for demonstration (e.g., finding AWS keys or generic secrets)
        rules = {
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "Generic Secret/Token": r"(?i)(secret|token|password)[\s=:>]+['\"]([^'\"]{8,})['\"]"
        }
        
        findings = []
        for risk, pattern in rules.items():
            matches = re.finditer(pattern, target_text)
            for match in matches:
                findings.append({
                    "vulnerability": risk,
                    "match": match.group(0),
                    "severity": "HIGH"
                })
                
        return Response({
            "status": "Scan complete",
            "findings_count": len(findings),
            "findings": findings
        }, status=status.HTTP_200_OK)