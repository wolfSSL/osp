#!/bin/bash

if [ -z ${HAPROXY_ROOT+x} ]; then
	echo HAPROXY_ROOT needs to be set to your haproxy source root directory
	exit 1
fi

if [ $# -ne 1 ]; then
	echo Usage: $0 '<haproxy config file>'
	exit 1
fi

$HAPROXY_ROOT/haproxy -f $1 -V -d
