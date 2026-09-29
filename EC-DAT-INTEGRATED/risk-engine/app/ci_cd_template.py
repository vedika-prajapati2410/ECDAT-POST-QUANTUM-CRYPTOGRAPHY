"""
CI/CD Gate Template
======================
Generates a ready-to-drop-in GitHub Actions workflow that re-runs a
scan on every push and fails the build if new Critical-risk crypto is
introduced -- operationalises "crypto-agility" as an ongoing practice
rather than a one-time audit. This is a template generator, not a
live CI integration (no CI runner exists in this sandbox) -- the YAML
it emits is real and usable as-is once ECDAT's API is deployed
somewhere reachable from the CI runner.
"""

import yaml


def generate_github_action(api_base_url: str = "https://your-ecdat-deployment.example.com", fail_on_tier: str = "Critical") -> str:
    workflow = {
        "name": "ECDAT Quantum-Readiness Gate",
        "on": {"push": {"branches": ["main"]}, "pull_request": {"branches": ["main"]}},
        "jobs": {
            "cbom-scan": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {"uses": "actions/checkout@v4"},
                    {
                        "name": "Generate CBOM and submit to ECDAT",
                        "run": (
                            "curl -s -X POST "
                            f"{api_base_url}/api/scans "
                            "-H \"Content-Type: application/json\" "
                            "-H \"X-API-Key: ${{ secrets.ECDAT_API_KEY }}\" "
                            "-d @cbom.json -o scan_result.json"
                        ),
                    },
                    {
                        "name": f"Fail build if any {fail_on_tier}-risk artefacts found",
                        "run": (
                            "COUNT=$(python3 -c \"import json; d=json.load(open('scan_result.json')); "
                            f"print(d['risk_tier_counts'].get('{fail_on_tier}', 0))\")\n"
                            "echo \"$COUNT " + f"{fail_on_tier}" + "-risk artefact(s) found\"\n"
                            "if [ \"$COUNT\" -gt 0 ]; then\n"
                            f"  echo \"::error::Build blocked -- {fail_on_tier}-risk cryptographic artefacts detected. "
                            "See scan_result.json for details.\"\n"
                            "  exit 1\n"
                            "fi"
                        ),
                    },
                ],
            }
        },
    }
    return yaml.safe_dump(workflow, sort_keys=False, default_flow_style=False)
