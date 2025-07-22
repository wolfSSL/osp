patch `xmlsec-master-wolfprov.patch` disables tests in master branch that uses RSA 512-bit key sizes which wolfProvider doesn't support.
patch `xmlsec-xmlsec-1_2_37-wolfprov.patch` disables tests in xmlsec-1_2_37 branch that uses RSA 512-bit key sizes and RC2 algorithms which wolfProvider doesn't support.
