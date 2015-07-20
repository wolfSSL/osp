SUBDIRS := echoclient-tcp echoserver-ssl

all: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@

.PHONY: all $(SUBDIRS)

clean:
	rm -rf *.o echoclient-tcp/echoclient-tcp echoserver-ssl/echoserver-ssl
