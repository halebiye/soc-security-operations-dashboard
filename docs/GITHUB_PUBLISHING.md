# Prepare the repository for GitHub

The ZIP contains the source folder, sample data, screenshots, career materials, and CI files. The working SQLite database, environments, caches, and secrets are excluded.

1. Extract the ZIP and open `soc-security-operations-dashboard`.
2. Run the application and tests using the README. Read the Arabic guide and practice the investigation walkthrough.
3. Create an empty GitHub repository named `soc-security-operations-dashboard` under `halebiye`. Do not add a separate generated README to the empty repository if you plan to push this one.
4. From the extracted folder, initialize and push the source:

```bash
git init
git add .
git commit -m "Build SOC Security Operations Dashboard"
git branch -M main
git remote add origin https://github.com/halebiye/soc-security-operations-dashboard.git
git push -u origin main
```

Use your normal GitHub authentication; do not store a token in these files. If the remote repository already contains work, integrate it deliberately rather than using a force push.

Suggested description:

> Offline Mini SIEM with explainable authentication detections, evidence-linked investigations, SQLite case workflow, and SOC reports. Synthetic data only.

Suggested topics:

`soc`, `siem`, `blue-team`, `cybersecurity`, `python`, `fastapi`, `sqlite`, `security-analytics`, `incident-response`, `portfolio`

After publishing, review GitHub Actions results. The supplied CI is configured but has not run remotely yet. Add the real repository URL to `LINKEDIN_POST.md`, `CV_PROJECT_ENTRY.md`, and `portfolio/project.json`, and pin the repository on your GitHub profile.
