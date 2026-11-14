# Verification

The initial public edition was executed against its included synthetic inputs:

| Check | Result |
| --- | --- |
| Normal unittest discovery | 274 tests passed |
| Separate contract regression checks | 9 checks passed |
| doctor, config-check and replay examples | All exited 0 |

The public diagnostic message uses generic target wording. Its existing assertion was changed
first, observed failing on the old message, then passed after the message correction. Other
application code and all synthetic fixture bytes were preserved in this edition.

Raw execution logs and machine observations are not included. These results establish offline
behavior in the verification environment; they do not certify cross-platform compatibility,
live Linux/NGINX producers, throughput, attack detection, enforcement or runtime recovery.
The four focused improvements in [STATUS](STATUS.md) remain pending in the regular suite.
