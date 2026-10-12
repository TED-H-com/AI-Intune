#!/usr/bin/env python3
"""Rebuild closed action scripts from the reviewed P2-02 protection/holder code."""
import hashlib, pathlib, re
root=pathlib.Path(__file__).resolve().parents[1]
source=root/'internal/scriptcatalog'
full=(source/'disk-safe-clean-v2.py').read_text()
safety=full.split('def unlink_checked(')[0]+full[full.index('def state_lock('):full.index('def save_summary(')]
core=(source/'disk-action-core.py').read_text()
for action,script in [('quarantine','disk-approved-quarantine-v1'),('delete','disk-approved-delete-v1'),('expire','disk-quarantine-expire-v1'),('restore','disk-quarantine-restore-v1')]:
    raw=(safety+'\nACTION = '+repr(action)+'\nSCRIPT_ID = '+repr(script)+'\n'+core).encode()
    (source/(script+'.py')).write_bytes(raw)
    digest=hashlib.sha256(raw).hexdigest()
    catalog=source/'catalog.go'
    catalog.write_text(re.sub(r'(\{"'+re.escape(script)+r'", "1", ")[a-f0-9]{64}',lambda m:m.group(1)+digest,catalog.read_text()))
    print(script,digest)
