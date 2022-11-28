
all: dwmstatus

dwmstatus: CFLAGS+= -g
dwmstatus: LDLIBS+= -lX11
dwmstatus: dwmstatus.o

install: dwmstatus
	mkdir -p $(DESTDIR)/$(PREFIX)/bin/
	mv dwmstatus $(DESTDIR)/$(PREFIX)/bin/
