# Portfolio website assets

These files are ready to use when adding the project to a personal cybersecurity portfolio. The screenshots show real views of the running synthetic-data application.

| Asset | Intended use |
| --- | --- |
| `project.json` | Structured project card, features, stack, and verified metrics |
| `project-cover.png` | Project image; exact desktop dashboard screenshot |
| `project-icon.svg` | Small project mark |
| `../docs/screenshots/dashboard-desktop.png` | Main screenshot / gallery image |
| `../docs/screenshots/alert-investigation.png` | Evidence and workflow detail |
| `../docs/screenshots/dashboard-mobile.png` | Responsive design demonstration |
| `../docs/screenshots/alert-queue.png` | Search and filtering demonstration |
| `../docs/screenshots/detection-rules.png` | Rule transparency |
| `../docs/screenshots/event-explorer.png` | Normalized telemetry |
| `../docs/screenshots/reports.png` | Export capabilities |

## Suggested project card copy

**SOC Security Operations Dashboard**

An offline Mini SIEM that turns synthetic authentication logs into explainable alerts. Built with FastAPI and SQLite, with evidence-linked investigations, analyst case notes, seven detection rules, and HTML/JSON/Markdown reporting.

**Skills demonstrated:** event normalization, correlation windows, SOC triage, evidence handling, transactional persistence, defensive API design, testing, and documentation.

## Embed example

Copy the chosen PNG into your website's public assets directory, then use an ordinary responsive image:

```html
<img src="/assets/soc-dashboard.png"
     alt="SOC dashboard showing synthetic authentication telemetry and prioritized alerts"
     loading="lazy" width="1480" height="1536"
     style="width:100%;height:auto;border-radius:12px">
```

For a cropped card, use your website's CSS with `object-fit:cover` and `object-position:top`; keep the full screenshot in the gallery so users can inspect it.

`repository_url` and `live_demo_url` are null because publication has not occurred. The planned repository URL is explicitly labeled. Fill the actual URL after publishing. Do not label this as an operational SOC or a publicly deployed service.
