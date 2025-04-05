# GitHub Advisory Project

This script loads security advisories from the [GitHub Advisory Database](https://github.com/github/advisory-database), classifies them by severity, saves them into folders, and creates zip archives per severity level.

## Features

- Parses local advisory JSON files
- Classifies by severity (`low`, `moderate`, `high`, `critical`)
- Saves advisories into structured folders
- Creates ZIP files for each severity
- Generates a CSV summary (with KEV support - default option) (if you don't need KEV support, comment it out and pull the non  KEV function in)
    ****to check KEV support, check this advisory - not many have a '1' next to them:
        GHSA-m8cj-3v68-3cxj,CVE-2024-34102,CRITICAL,magento/community-edition,Packagist,Magento Open Source affected by an Im        proper Restriction of XML External Entity Reference ('XXE') vulnerability,1

## Usage
#First do a git clone on the advisory DB from Github
git clone git@github.com:github/advisory-database.git

```bash
python3 project3.py

