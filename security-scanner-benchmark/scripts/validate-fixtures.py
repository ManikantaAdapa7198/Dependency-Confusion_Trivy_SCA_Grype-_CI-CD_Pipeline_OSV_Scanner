import json
from pathlib import Path

data = json.loads(
    Path("expected-results/ground-truth.json").read_text()
)

ids = [x["test_id"] for x in data["findings"]]
assert len(ids) == len(set(ids)), "Duplicate test IDs"

for finding in data["findings"]:
    assert finding["test_id"]
    assert finding["category"]
    assert finding["expected_status"]

print("Ground-truth validation passed.")
print("Test cases:", len(ids))
