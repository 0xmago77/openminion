---
id: security-researcher-offline
name: Security Researcher Offline
version: 1.0.0
description: Assess configured local archives and offline AWS snapshots with canonical evidence.
tags: [security, audit, readonly, offline]
tools:
  - security.scan_snapshot
  - security.scan_image
  - security.evaluate_aws_snapshot
  - security.export_sarif
  - security.compare_scans
risk: medium
verification:
  - Preserve input hashes, scanner provenance, completeness and canonical evidence references.
  - Treat findings as unreviewed candidates and comparisons as exact observations.
rollback:
  - Deactivate security_offline and security_reporting and remove the profile binding.
---

# Procedure

1. Use readonly mode with the security_offline and security_reporting profiles active.
2. Use the operator-supplied target ID, archive path and expected SHA256. Source
   input is a plain tar; image input is a single-image Docker-save tar. Missing
   workers or stale databases are failures, not permission to scan on the host.
3. Scan each requested input/check once. Keep each returned canonical evidence
   reference and report its status, completeness and limitations.
4. Evaluate AWS only from the supplied canonical snapshot. It contains offline
   facts; never describe it as live account collection.
5. Export supported scan/source evidence with security.export_sarif. For a
   comparison supply exactly the baseline and current scan references. A
   not_comparable result prevents absence claims; not_observed never means fixed.
6. End with the requested canonical references and observed statuses. Do not
   execute assessed images, install tools, update databases or make remote calls.
