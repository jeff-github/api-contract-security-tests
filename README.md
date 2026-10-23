# API Contract & Security Tests

Python/pytest checks for response schemas, authentication failures, invalid inputs,
headers, role-sensitive endpoints and stability. A separate configurable security
runner checks RBAC and cross-scope object access.

## Setup (Python 3.10+)
```powershell
python -m pip install -r requirements.txt
$env:PORTAL_BASE_URL="http://localhost:3000"
$env:PORTAL_TOKEN="YOUR_TEST_TOKEN"
python -m pytest test_portal_api.py -v
```
The target must implement the `/api/v1/portal` routes described in the test file.
No demo backend is bundled. Without an explicit base URL, integration tests skip.
Some checks send POST/PATCH requests; use a disposable authorized environment.

## Security runner
Copy `config.example.yaml` to `config.yaml`, add synthetic IDs, test tokens and
endpoints, then run `python portal_sec_qa.py --config config.yaml --out out`.
The sample has no endpoints and performs no meaningful assessment until configured.
The minimal YAML parser supports a subset of YAML; inspect it before extending config.
Reports may contain raw response snippets. Keep them private.

These are response-contract checks, not Pact contracts. Some generic-role checks
accept 200 or 403; configure explicit role expectations in the security runner.
CI checks compilation and collection, not a live API or security certification.

## Status
Private portfolio preparation copy of existing project code. Original credentials,
run data and environment defaults are excluded. No open-source license is granted;
confirm ownership and sharing rights before making this repository public.
