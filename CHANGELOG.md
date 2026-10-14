Release Summary
=========
1.3.0 (October, 2026)
------
* Added Static Application Security Testing (SAST) scanning support via `invokesastscan` command.
* Added Software Composition Analysis (SCA) scanning support via `invokescascan` command.
* Upgraded AppScan SDK from v1.1.5 to v1.1.12.
* Support for combined SAST + SCA scans by default, with `--staticAnalysisOnly` for SAST-only scans.
* Support for IRX generation (`createIRX`) and direct upload (`uploadDirect`) scan methods.
* Threshold-based build failure (`failbuildif`) support for SAST and SCA scans.

1.2.1 (September, 2026)
------
* Email notifications are now managed centrally through ASoC Account Settings. The per-scan email notification option has been removed.

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
