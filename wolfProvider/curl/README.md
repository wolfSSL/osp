`wolfProvider/curl/curl-8_4_0-wolfprov.patch` adds support for testing curl 
`8.4.0` with wolfProvider FIPS in Jenkins. This patch is only needed when 
testing curl with Jenkins. It disables a non crypto related test that IDN 
with different languages.
