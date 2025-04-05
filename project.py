import pandas as pd
import glob
import json

#repo_path = '/advisory-database/advisories/github-reviewed/**/**/**/*.json'
repo_path = 'advisory-database/advisories/github-reviewed/2025/01/GHSA-222v-cx2c-q2f5/GHSA-222v-cx2c-q2f5.json'

json_files = glob.glob(repo_path, recursive=True)

data = []

for file in json_files:
    with open(file, 'r') as f:
        json_data = json.load(f)
        data.append(json_data)

gh_adv = pd.DataFrame(data)
gh_adv.info()

