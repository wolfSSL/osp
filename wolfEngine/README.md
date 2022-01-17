# wolfSSL Open Source Project Ports with wolfEngine

The goal of the wolfEngine project is to replace the crypto used by OpenSSL
with wolfCrypt or wolfCrypt FIPS, with the least amount of changes possible.

Each of the project directories has both a patch file and a reference to a
submodule for the project at the commit for the patch. After cloning the OSP
repository, run the command `git submodule init && git submodule update`. This
will clone all the submodules. If the OSP repository hasn't been cloned yet,
clone it with the command:

    git clone --recurse-submodules https://github.com/wolfSSL/osp

To apply a patch file, change to the project's directory and run
`patch -p1 <../PROJ-patch.txt`. Build the project normally.

The projects supported are:

| Directory | Project | Repository |
| :--- | :--- | :--- |
|libssh|[libssh](https://www.libssh.org)|[repo link](https://git.libssh.org/projects/libssh.git)|
|libssh2|[libssh2](https://libssh2.org)|[repo link](https://github.com/libssh2/libssh2.git)|
|radsecproxy|[radsecproxy](https://radsecproxy.github.io)|[repo link](https://github.com/radsecproxy/radsecproxy.git)|


# Licensing

wolfSSL and wolfCrypt are either licensed for use under the GPLv2 (or at your
option any later version) or a standard commercial license. For users who
cannot use wolfSSL under GPLv2 (or any later version), a commercial license to
wolfSSL and wolfCrypt is available. For license inquiries, please contact
wolfSSL Inc. directly at licensing@wolfssl.com.

All non-wolfSSL projects in this repository are licensed under their
respective project licenses.

# Support

For support or build issues, please contact the wolfSSL support team at
support@wolfssl.com.
