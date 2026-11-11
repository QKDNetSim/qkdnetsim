# Changelog

## [3.1.5] - 2026-11-11
### Change
- ETSI004 application: auth tag is by default set to 32 zeros
- KMS application: PQC key generation fixed

## [3.1.4] - 2026-09-21
### Change
- Examples: tracking statistics improved
- ETSI004 application Close connection bug fixed; CheckQueues and get_key logic improved.
- ETSI004 introducing trace for keys consumed for encryption/decryption and authentication/deauthantication
- ETSI014 introducing trace for keys consumed for encryption/decryption and authentication/deauthantication
- KMS application traces changed. Introducing trace for keys provided (from QBuffers to SBuffers) and delivered (from SBuffers to end-user applications) 
- KMS application release ETSI004 Association bug fixed. Key are traced as wasted. No keys are restored back to QBuffers

## [3.1.3] - 2026-08-27
### Change
- PQC support included
- ETSI 004 application bug fixed
- KMS-KMS communication improved

## [3.1.2] - 2026-02-03
### Change
- License update

## [3.1.1] - 2025-12-25
### Added
- Initial public release of the Quantum Key Distribution Network Simulation Module for NS-3 (full "network KML mode" version)
