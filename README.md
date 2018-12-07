# MITRE ATT&CK Evaluation DB

Originally featured in this blog post: https://securityriskadvisors.com/blog/a-closer-look-at-mitre-attck-evaluation-data/

## Database

### Columns

- vendor
- techniquename
- techniqueid
- Telemetry
    - yes or no
- Indicator of Compromise
    - yes or no
- Enrichment
    - yes or no
- General Behavior
    - yes or no
- Specific Behavior
    - yes or no
- Tainted
    - combination of 5 main detection categories
- Delayed
    - combination of 5 main detection categories
- Configuration Change
    - combination of 5 main detection categories

### Example Queries

recommended browser: http://inloop.github.io/sqlite-viewer/

Techniques with no detections

```
select count(Vendor) as Product_Misses, techniquename, techniqueid from edr where Telemetry = 'no' AND Indicator = 'no' AND Enrichment = 'no' AND General = 'no' AND Specific = 'no' group by techniqueid ORDER BY Product_Misses DESC 
```

Techniques with no detection (filtered for only general and specific behaviors)

```
select count(Vendor) as Product_Misses, techniquename, techniqueid from edr where General = 'no' AND Specific = 'no' group by techniqueid ORDER BY Product_Misses DESC
```

Total detections by vendor

```
select vendor, count(vendor) as total_detections from edr WHERE Telemetry = 'yes' OR Indicator = 'yes' OR Enrichment = 'yes' OR General = 'yes' or Specific = 'yes' group by vendor; 
```

Total detections by vendor (filtered for only general and specific behaviors)

```
select vendor, count(vendor) as total_detections from edr WHERE General = 'yes' or Specific = 'yes' group by vendor;
```

Results for single technique

```
select * from edr where techniqueid == 'T1110'
```

Results for multiple techniques (filtered for only general and specific behaviors)

```
select vendor,techniquename,techniqueid,general,specific,tainted,delayed,configuration from edr where techniqueid in ('T1110','T1048') and 'yes' in (general, specific) order by techniqueid
```

## Report

The report.html file contains multiple tables, each containing the detection results for a single technique.

## JSON

Original JSON data from the evaluations site

## Links

- MITRE Evaluations: https://attackevals.mitre.org/
- MITRE ATT&CK: https://attack.mitre.org/
