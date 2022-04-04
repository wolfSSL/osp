This folder contains patches for git to work with wolfSSL. Patches make it
easier to add support for newer versions of a target library. The format of
the patch names is:
    `git-<version>.patch`
Instructions for applying each patch are included in the patch files.

# Other SSL dependencies

`git` uses external dependencies for most of its communication protocols. The
two more common protocols used within `git` are https and ssh. `git` builds and
links against the system available curl for http and https support and uses the
`ssh` utility that is available at runtime in `$PATH` for ssh support. To use
only wolfSSL in git make sure that all dependencies are using wolfSSL. curl can
be built using wolfSSL using a [configure option](https://everything.curl.dev/source/build/tls#wolfssl)
while you can build OpenSSH to against wolfSSL using our patches found
[here](../openssh-patches).
