`wolfProvider/openldap/openldap-OPENLDAP_REL_ENG_2_6_7-debian-wolfprov.patch` adds support
for testing OpenLDAP `OPENLDAP_REL_ENG_2_6_7` with non-FIPS debian wolfProvider. This patch
skips the test076-authid-rewrite test due to RC4 cipher incompatibility.
