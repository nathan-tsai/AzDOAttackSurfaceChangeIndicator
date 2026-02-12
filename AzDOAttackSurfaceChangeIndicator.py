import os
import requests
import base64
import re
import json
from datetime import datetime
import pytz

# ===========================
# CONFIGURATION
# ===========================
ORG = os.environ["AZDO_ORG"]
PAT = os.environ["AZDO_PAT"]
API_VERSION = "7.0"

BASE_URL = f"https://dev.azure.com/{ORG}"

AUTH_HEADER = {
    "Authorization": "Basic " + base64.b64encode(f":{PAT}".encode()).decode(),
    "Content-Type": "application/json"
}

CACHE_FILE = "pr_cache.json"

SECURITY_SECTION_START = "<!-- SECURITY-IMPACT-START -->"
SECURITY_SECTION_END = "<!-- SECURITY-IMPACT-END -->"

# ===========================
# CACHE
# ===========================
try:
    with open(CACHE_FILE) as f:
        PR_CACHE = json.load(f)
except FileNotFoundError:
    PR_CACHE = {}

def save_cache():
    with open(CACHE_FILE, "w") as f:
        json.dump(PR_CACHE, f)

# ===========================
# AZDO API HELPERS
# ===========================
def list_projects():
    r = requests.get(
        f"{BASE_URL}/_apis/projects?api-version={API_VERSION}",
        headers=AUTH_HEADER
    )
    r.raise_for_status()
    return r.json()["value"]

def list_repos(project):
    r = requests.get(
        f"{BASE_URL}/{project}/_apis/git/repositories?api-version={API_VERSION}",
        headers=AUTH_HEADER
    )
    r.raise_for_status()
    return r.json()["value"]

def list_active_prs(project, repo_id):
    r = requests.get(
        f"{BASE_URL}/{project}/_apis/git/repositories/{repo_id}/pullrequests"
        f"?status=active&api-version={API_VERSION}",
        headers=AUTH_HEADER
    )
    r.raise_for_status()
    return r.json()["value"]

def get_latest_iteration_and_changes(project, repo_id, pr_id):
    r = requests.get(
        f"{BASE_URL}/{project}/_apis/git/repositories/{repo_id}/pullRequests/{pr_id}/iterations"
        f"?api-version={API_VERSION}",
        headers=AUTH_HEADER
    )
    r.raise_for_status()

    iterations = r.json()["value"]
    if not iterations:
        return None, []

    iteration_id = iterations[-1]["id"]

    r = requests.get(
        f"{BASE_URL}/{project}/_apis/git/repositories/{repo_id}/pullRequests/{pr_id}"
        f"/iterations/{iteration_id}/changes?api-version={API_VERSION}",
        headers=AUTH_HEADER
    )
    r.raise_for_status()

    return iteration_id, r.json()["changes"]

# ===========================
# THREAT MODELING (NOT SAST)
# ===========================
def infer_threat_model_signals(changes):
    signals = set()
    score = 0

    for c in changes:
        path = c["item"]["path"].lower()

        if re.search(r"(auth|identity|rbac|permission|guard)", path):
            signals.add("Sensitive trust boundary modified")
            score += 2

        if re.search(r"(controller|routes|api)", path):
            signals.add("API surface changed")
            score += 1

        if re.search(r"(data|repository|dao)", path):
            signals.add("Data access layer modified")
            score += 1

    # Threshold to avoid noise
    if score < 2:
        return []

    return sorted(signals)

def build_pr_section(signals):
    bullets = "\n".join(f"- {s}" for s in signals)

    return f"""
{SECURITY_SECTION_START}
<details>
<summary>Security impact (auto-generated)</summary>

**Threat Modeling Notice**

This section is generated as part of continuous threat modeling.

**Scope**
- Architectural and design-level security impact
- Trust boundaries, sensitive modules, and API exposure
- Not a vulnerability scanner
- Does not replace SAST (handled separately)

**Observed signals**
{bullets}

_No action required if this change is expected and properly controlled._

</details>
{SECURITY_SECTION_END}
""".strip()

def update_pr_description(project, repo_id, pr_id, existing_desc, section):
    if section:
        if SECURITY_SECTION_START in existing_desc:
            updated = re.sub(
                f"{SECURITY_SECTION_START}.*?{SECURITY_SECTION_END}",
                section,
                existing_desc,
                flags=re.S
            )
        else:
            updated = existing_desc + "\n\n" + section
    else:
        updated = re.sub(
            f"{SECURITY_SECTION_START}.*?{SECURITY_SECTION_END}",
            "",
            existing_desc,
            flags=re.S
        )

    r = requests.patch(
        f"{BASE_URL}/{project}/_apis/git/repositories/{repo_id}/pullRequests/{pr_id}"
        f"?api-version={API_VERSION}",
        headers=AUTH_HEADER,
        json={"description": updated}
    )
    r.raise_for_status()

# ===========================
# MAIN
# ===========================
def run():
    for project in list_projects():
        project_name = project["name"]

        for repo in list_repos(project_name):
            repo_id = repo["id"]

            for pr in list_active_prs(project_name, repo_id):
                pr_id = pr["pullRequestId"]
                cache_key = f"{project_name}:{repo_id}:{pr_id}"

                iteration_id, changes = get_latest_iteration_and_changes(
                    project_name, repo_id, pr_id
                )

                if iteration_id is None:
                    continue

                if PR_CACHE.get(cache_key) == iteration_id:
                    continue  # no new changes

                PR_CACHE[cache_key] = iteration_id

                signals = infer_threat_model_signals(changes)
                section = build_pr_section(signals)
                update_pr_description(
                    project_name,
                    repo_id,
                    pr_id,
                    pr.get("description", ""),
                    section
                )

    save_cache()

if __name__ == "__main__":
    pacific = pytz.timezone("US/Pacific")
    print("Threat modeling run:", datetime.now(pacific))
    run()
