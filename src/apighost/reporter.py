"""
APIGhost Reporter

Generates scan reports in various formats: JSON, HTML, Markdown, and SARIF.
"""

import json
import os
from typing import Any
from datetime import datetime

from jinja2 import Environment, FileSystemLoader

from apighost.models import ChainResult
from apighost import __version__

# Default paths
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")


class Reporter:
    """Generates scan reports in various formats."""

    def __init__(self, results: list[ChainResult]):
        self.results = results
        self.timestamp = datetime.now().isoformat()
        
        # Summary statistics
        self.total = len(results)
        self.confirmed = sum(1 for r in results if r.verdict.value == "CONFIRMED")
        self.likely = sum(1 for r in results if r.verdict.value == "LIKELY")
        self.possible = sum(1 for r in results if r.verdict.value == "POSSIBLE")
        self.secure = sum(1 for r in results if r.verdict.value == "SECURE")
        self.errors = sum(1 for r in results if r.verdict.value == "ERROR")
        
        # Ensure template dir exists
        os.makedirs(TEMPLATE_DIR, exist_ok=True)
        self._create_default_templates()
        
        self.env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))

    def _create_default_templates(self) -> None:
        """Create default Jinja2 templates if they don't exist."""
        html_path = os.path.join(TEMPLATE_DIR, "report.html.j2")
        md_path = os.path.join(TEMPLATE_DIR, "report.md.j2")
        
        if not os.path.exists(html_path):
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(self._default_html_template())
                
        if not os.path.exists(md_path):
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(self._default_md_template())

    def _default_html_template(self) -> str:
        return """<!DOCTYPE html>
<html>
<head>
    <title>APIGhost Scan Report</title>
    <style>
        body { font-family: system-ui, sans-serif; margin: 40px; color: #333; }
        h1 { color: #2c3e50; }
        .summary { display: flex; gap: 20px; margin-bottom: 30px; }
        .stat-box { padding: 15px; border-radius: 8px; text-align: center; min-width: 120px; }
        .stat-box h3 { margin: 0 0 10px 0; font-size: 14px; text-transform: uppercase; color: #666; }
        .stat-box p { margin: 0; font-size: 24px; font-weight: bold; }
        .bg-red { background: #fee2e2; color: #991b1b; }
        .bg-yellow { background: #fef3c7; color: #92400e; }
        .bg-green { background: #dcfce7; color: #166534; }
        .bg-gray { background: #f3f4f6; color: #374151; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; }
        .verdict-CONFIRMED { color: #dc2626; font-weight: bold; }
        .verdict-LIKELY { color: #d97706; font-weight: bold; }
        .verdict-SECURE { color: #16a34a; }
    </style>
</head>
<body>
    <h1>APIGhost Scan Report</h1>
    <p>Generated on {{ timestamp }} | APIGhost v{{ version }}</p>
    
    <div class="summary">
        <div class="stat-box bg-gray"><h3>Total Scanned</h3><p>{{ total }}</p></div>
        <div class="stat-box bg-red"><h3>Confirmed BOLA</h3><p>{{ confirmed }}</p></div>
        <div class="stat-box bg-yellow"><h3>Likely BOLA</h3><p>{{ likely }}</p></div>
        <div class="stat-box bg-green"><h3>Secure</h3><p>{{ secure }}</p></div>
    </div>

    <h2>Discovered Attack Chains</h2>
    <table>
        <tr>
            <th>Chain ID</th>
            <th>Resource</th>
            <th>Variant</th>
            <th>Verdict</th>
            <th>Score</th>
            <th>Attack Endpoint</th>
        </tr>
        {% for result in results %}
        <tr>
            <td>{{ result.chain.chain_id }}</td>
            <td>{{ result.chain.resource_name }}</td>
            <td>{{ result.chain.variant.value }}</td>
            <td class="verdict-{{ result.verdict.value }}">{{ result.verdict.value }}</td>
            <td>{{ "%.2f"|format(result.score) }}</td>
            <td>{{ result.chain.attack.method.value if result.chain.attack else result.chain.read.method.value }} {{ result.chain.attack.path if result.chain.attack else result.chain.read.path }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>"""

    def _default_md_template(self) -> str:
        return """# APIGhost Scan Report

**Generated:** {{ timestamp }}  
**Version:** APIGhost v{{ version }}

## Summary
- **Total Chains Scanned:** {{ total }}
- **Confirmed BOLA:** {{ confirmed }} 🔴
- **Likely BOLA:** {{ likely }} 🟠
- **Possible:** {{ possible }} 🟡
- **Secure:** {{ secure }} 🟢
- **Errors:** {{ errors }} ⚪

## Detailed Results

| Chain ID | Resource | Variant | Verdict | Score | Attack Endpoint |
|----------|----------|---------|---------|-------|-----------------|
{% for result in results -%}
| {{ result.chain.chain_id }} | {{ result.chain.resource_name }} | {{ result.chain.variant.value }} | **{{ result.verdict.value }}** | {{ "%.2f"|format(result.score) }} | `{{ result.chain.attack.method.value if result.chain.attack else result.chain.read.method.value }} {{ result.chain.attack.path if result.chain.attack else result.chain.read.path }}` |
{% endfor %}
"""

    def get_template_data(self) -> dict[str, Any]:
        """Get the data dictionary used for Jinja templates."""
        return {
            "version": __version__,
            "timestamp": self.timestamp,
            "total": self.total,
            "confirmed": self.confirmed,
            "likely": self.likely,
            "possible": self.possible,
            "secure": self.secure,
            "errors": self.errors,
            "results": self.results,
        }

    def generate_json(self) -> str:
        """Generate a JSON report."""
        report = {
            "tool": "APIGhost",
            "version": __version__,
            "timestamp": self.timestamp,
            "summary": {
                "total": self.total,
                "confirmed": self.confirmed,
                "likely": self.likely,
                "secure": self.secure,
                "errors": self.errors
            },
            "results": []
        }

        for result in self.results:
            report["results"].append({
                "chain_id": result.chain.chain_id,
                "resource": result.chain.resource_name,
                "variant": result.chain.variant.value,
                "verdict": result.verdict.value,
                "score": round(result.score, 4),
                "signals": {k: round(v, 4) for k, v in result.signals.items()},
                "attack_endpoint": f"{result.chain.attack.method.value if result.chain.attack else result.chain.read.method.value} {result.chain.attack.path if result.chain.attack else result.chain.read.path}",
                "create_status": result.create_status,
                "resource_id": result.resource_id,
                "read_as_owner_status": result.read_as_owner_status,
                "read_as_attacker_status": result.read_as_attacker_status,
                "teardown_success": result.teardown_success,
                "duration_ms": result.duration_ms,
                "error": result.error,
            })
            
        return json.dumps(report, indent=2)

    def generate_html(self) -> str:
        """Generate an HTML report using Jinja2."""
        template = self.env.get_template("report.html.j2")
        return template.render(**self.get_template_data())

    def generate_markdown(self) -> str:
        """Generate a Markdown report using Jinja2."""
        template = self.env.get_template("report.md.j2")
        return template.render(**self.get_template_data())

    def generate_sarif(self) -> str:
        """Generate a SARIF (Static Analysis Results Interchange Format) report."""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "APIGhost",
                        "informationUri": "https://github.com/Arul-AGC/APIGhost",
                        "version": __version__,
                        "rules": [
                            {
                                "id": "API1-BOLA",
                                "name": "Broken Object Level Authorization",
                                "shortDescription": {"text": "A user can access or modify an object they do not own."}
                            }
                        ]
                    }
                },
                "results": []
            }]
        }
        
        for result in self.results:
            if result.verdict.value in ("CONFIRMED", "LIKELY"):
                level = "error" if result.verdict.value == "CONFIRMED" else "warning"
                attack_str = f"{result.chain.attack.method.value if result.chain.attack else result.chain.read.method.value} {result.chain.attack.path if result.chain.attack else result.chain.read.path}"
                
                sarif_result = {
                    "ruleId": "API1-BOLA",
                    "level": level,
                    "message": {
                        "text": f"BOLA ({result.chain.variant.value}) detected on {attack_str}. Attacker received HTTP {result.read_as_attacker_status} (Score: {result.score:.2f})."
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": attack_str.split(" ")[1]
                            }
                        }
                    }]
                }
                sarif["runs"][0]["results"].append(sarif_result)
                
        return json.dumps(sarif, indent=2)
        
    def save(self, filepath: str, format: str = "json") -> None:
        """Generate and save the report to the specified file."""
        format = format.lower()
        if format == "html":
            content = self.generate_html()
        elif format == "md" or format == "markdown":
            content = self.generate_markdown()
        elif format == "sarif":
            content = self.generate_sarif()
        else:
            content = self.generate_json()
            
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
