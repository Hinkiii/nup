# NUP v2

A package for decrypted NX (Nintendo Switch 1/2) dumps, derived
from the NSP layout with the encryption and signatures removed.

Instead of using sigs and encryption it uses hashes that can be 
checked and verifed before being run by an emulator.

## Goal

Take the NSP structure - partition filesystem holding content files plus
content metadata - and strip everything that requires keys:

- no NCA-level crypto (XTS header, key areas, CTR/BKTR sections)
- no RSA signatures (fixed-key, NPDM, ticket/cert chain)
- content hashes kept instead, so an emulator can verify data integrity
  and validity later

Extra things that will exist in v2:

- update dumps for games will be diffed and only the diff stored
 so it can be applied to the base (this might be an issue with games
 we dont have the base of, in those cases, store update as base(?))

## Status

Designing.

## v1

The v1 format SPEC (own container, per-file zstd, TOC hashes) and its 
Python reference implementation are on the `meow` branch.
