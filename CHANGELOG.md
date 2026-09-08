Release Summary
=========
1.2.1 (September, 2026)
------
* Email notifications are now managed centrally in AppScan Account Settings. The per-scan email notification option has been removed; existing `--emailNotification` pipeline values are ignored with a warning for compatibility.
* Added supply chain security hardening (SCVS-4.18, SCAL-PKGDEP-2, SCAL-PKGDEP-3): Maven enforcer rules, dependency lockfile with SHA-256 checksums, CycloneDX SBOM generation, and Maven wrapper for reproducible builds.

1.2.0 (December, 2024)
------
* Support for executing DAST Scans via HCL AppScan 360° v1.3 and above.
* Bug fixes

1.1.0 (March, 2024)
------
* Migration to version 4 of ASoC REST APIs
* Added support for downloading scan log file
* Bug fixes

1.0.0 (September, 2023)
------
* Initial release.
