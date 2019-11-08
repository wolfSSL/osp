#!/bin/bash

set -e

make tests LTESTS=connect
make tests LTESTS=proxy-connect
make tests LTESTS=proto-version
make tests LTESTS=proto-mismatch
make tests LTESTS=exit-status
make tests LTESTS=envpass
make tests LTESTS=transfer
make tests LTESTS=banner
make tests LTESTS=rekey
make tests LTESTS=stderr-data
make tests LTESTS=stderr-after-eof
make tests LTESTS=broken-pipe
make tests LTESTS=try-ciphers
make tests LTESTS=yes-head
make tests LTESTS=login-timeout
make tests LTESTS=agent
make tests LTESTS=agent-getpeereid
make tests LTESTS=agent-timeout
make tests LTESTS=agent-ptrace
make tests LTESTS=keyscan
make tests LTESTS=keygen-change
make tests LTESTS=keygen-convert
make tests LTESTS=key-options
make tests LTESTS=scp
make tests LTESTS=sftp
make tests LTESTS=sftp-chroot
make tests LTESTS=sftp-cmds
make tests LTESTS=sftp-badcmds
make tests LTESTS=sftp-batch
make tests LTESTS=sftp-glob
make tests LTESTS=sftp-perm
make tests LTESTS=reconfigure
make tests LTESTS=dynamic-forward
make tests LTESTS=forwarding
make tests LTESTS=multiplex
make tests LTESTS=reexec
make tests LTESTS=brokenkeys
make tests LTESTS=cfgmatch
make tests LTESTS=addrmatch
make tests LTESTS=localcommand
make tests LTESTS=forcecommand
make tests LTESTS=portnum
make tests LTESTS=kextype
make tests LTESTS=host-expand
make tests LTESTS=keys-command
make tests LTESTS=forward-control
make tests LTESTS=integrity
make tests LTESTS=krl

echo '####################'
echo '# ALL TESTS PASSED #'
echo '####################'
