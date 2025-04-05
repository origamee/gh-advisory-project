#advisory-database/advisories/github-reviewed/2025/01/GHSA-222v-cx2c-q2f5/GHSA-222v-cx2c-q2f5.json

import os
import zipfile

root_dir = "advisory-database/advisories/github-reviewed"  # Replace with the actual path
total_files = 0
for root, _, files in os.walk(root_dir):
    for file in files:
        with open(file, 'r') as json_file:
            data = json.load(json.file)
            if data['severity'] == "MODERATE":
                print("found")

