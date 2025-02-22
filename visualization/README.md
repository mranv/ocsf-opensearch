# OCSF Visualization Tools

Tools for creating and managing OpenSearch dashboards for OCSF data visualization.

## Prerequisites

```bash
pip install opensearchpy urllib3
```

## Components

### HTTP Activity Visualizer
```bash
python http_activity_visualizer.py [options]
```

### Dashboard Generator
```bash
python dashboard_generator.py [options]
```

## Available Visualizations
- HTTP Methods Distribution (Pie)
- Status Codes Timeline (Line)
- Geographic Distribution (Map)
- Error Rates (Bar)
- Response Times (Histogram)

## Dashboard Templates
Located in `dashboards/` directory:
- HTTP Overview (`http_overview.ndjson`)
- Security Overview
- Compliance Dashboard
- System Activity Dashboard

## Customization
1. Modify visualization templates in `templates/`
2. Update mappings in `mappings/`
3. Adjust time ranges in scripts
4. Configure refresh intervals