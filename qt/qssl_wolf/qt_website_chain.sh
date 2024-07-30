#!/bin/sh

CHAIN_INFO=www_qt_io_chain.info

if [ -e $CHAIN_INFO ]; then
    rm -f $CHAIN_INFO
fi
# 
CHAIN=`echo -n|openssl s_client -connect www.qt.io:443 -nameopt lname < /dev/null 2> /dev/null|grep -i commonName=|grep -i s:|awk -v FS=[,:] '{print $(NF)}'|awk -v FS=[=] '{print $2}' >> $CHAIN_INFO`

#for CN in $CHAIN ; do
#    echo $CN >> $CHAIN_INFO
#done


