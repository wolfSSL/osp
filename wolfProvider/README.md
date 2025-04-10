# wolfSSL Open Source Project Ports with wolfProvider

The goal of the wolfProvider project is to replace the crypto used by OpenSSL
with wolfCrypt or wolfCrypt FIPS, with the least amount of changes possible.

Each of the project directories a patch file for a specific version of the Open
Source Project.

To apply a patch file, change to the project's directory and run
`patch -p1 <../PROJ-patch.txt`. Build the project normally.

The projects supported are:

| Directory | Project | Repository |
| :--- | :--- | :--- |
|strongswan|[strongswan](https://strongswan.org/)|[repo link](https://github.com/strongswan/strongswan.git)|


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
