# Download YARA rules from VALHALLA (demo key) - UC-07 Windows
# Source: S2 pp.50-51.  pip install valhallaAPI
# NOTE: the demo key returns a limited demo ruleset (ISSUE-025).
from valhallaAPI.valhalla import ValhallaAPI

v = ValhallaAPI(api_key="1111111111111111111111111111111111111111111111111111111111111111")
response = v.get_rules_text()

with open("yara_rules.yar", "w") as fh:
    fh.write(response)
