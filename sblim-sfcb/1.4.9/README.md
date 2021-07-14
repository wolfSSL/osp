# Building sblim-sfcb with wolfSSL
+ Configure wolfSSL with `./configure --enable-sblim-sfcb`. Add `--enable-debug` if you're going to be debugging.
+ `make` and `sudo make install` wolfSSL into /usr/local.
+ Download sblim-sfcb-1.4.9 with `curl -L -O http://downloads.sourceforge.net/sblim/sblim-sfcb-1.4.9.tar.bz2`.
+ Unarchive this tar ball with `tar xvf sblim-sfcb-1.4.9.tar.bz2` and `cd sblim-sfcb-1.4.9`.
+ Apply the sblim-sfcb-1.4.9.patch file with `patch -p1 < sblim-sfcb-1.4.9-wolfssl.patch` (assuming the patch file is in the sblim-sfcb-1.4.9 directory; adjust the path according to your situation). This patch adds wolfSSl support.
+ Additional patches are needed to get everything building. These aren't wolfSSL-related. Download them with `curl -O https://raw.githubusercontent.com/openembedded/meta-openembedded/master/meta-oe/recipes-extended/sblim-sfcb/sblim-sfcb/0001-include-stdint.h-system-header-for-UINT16_MAX.patch && curl -O https://raw.githubusercontent.com/openembedded/meta-openembedded/master/meta-oe/recipes-extended/sblim-sfcb/sblim-sfcb/sblim-sfcb-1.4.9-fix-ftbfs.patch && curl -O https://raw.githubusercontent.com/openembedded/meta-openembedded/master/meta-oe/recipes-extended/sblim-sfcb/sblim-sfcb/sblim-sfcb-1.4.9-fix-sfcbinst2mof.patch`. Apply the patches with `patch -p1 < sblim-sfcb-1.4.9-fix-sfcbinst2mof.patch && patch -p1 < sblim-sfcb-1.4.9-fix-ftbfs.patch && patch -p1 < 0001-include-stdint.h-system-header-for-UINT16_MAX.patch`.
+ Regenerate the configure script with `autoreconf -ivf`.
+ Configure sblim-sfcb with `./configure --enable-tests --enable-ssl --with-wolfssl=/usr/local`. Update the path if you've installed wolfSSL using a different prefix than /usr/local.
+ Run `make` to compile. The dependencies in Makefile.am aren't quite right. Running make in parallel (i.e. with `-j<a number greater than 1>`) may not work.

## Testing
We've had limited success getting `make test` to pass, both with OpenSSL and wolfSSL. As a result, running the full test suite isn't a particularly useful exercise at this time. However, you can run a simple test to verify that wolfSSL is being used.
+ Run `sudo make install` and `sudo make postinstall`.
+ In one terminal window, launch the sfcbd with `sudo LD_LIBRARY_PATH=/usr/local/lib /usr/local/sbin/sfcbd`.
+ In another window, `cd test/xmltest` and run `sudo PERL_LWP_SSL_CA_FILE=/usr/local/etc/sfcb/server.pem wbemcat -p 5989 -t https ./associatorNames.IndSubscription.xml`. You should see an XML response like this:
    ```
    <?xml version="1.0" encoding="utf-8" ?>
    <CIM CIMVERSION="2.0" DTDVERSION="2.0">
    <MESSAGE ID="4711" PROTOCOLVERSION="1.0">
    <SIMPLERSP>
    <IMETHODRESPONSE NAME="AssociatorNames">
    <IRETURNVALUE>
    </IRETURNVALUE>
    </IMETHODRESPONSE>
    </SIMPLERSP>
    </MESSAGE>
    </CIM>
    ```
+ If you've built wolfSSL with `--enable-debug`, you should see a flurry of debug messages in the window running sfcbd. If not, you can view the TLS traffic in Wireshark.