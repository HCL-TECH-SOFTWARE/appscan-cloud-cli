CHANGELOG
=========
1.0.0 (September, 2023)
------
* Initial release.

1.1.0 (March, 2024)
------
* Migrated AppScan on Cloud Api's from version v2 to v4
* Added support for downloading scan log file
  - The scan log file will be downloaded in zip format once the scan is completed
* TrafficFile option in InvokeDynamicScan command is deprecated. It is replaced by loginSequenceFile. 
* Bug fixes : 
  - Fixed an incorrect message shown when scanFile option is left empty
  - Added an error message when the network is disconnected while the scan is in progress
  - Changed ClientType Parameter as per convention
