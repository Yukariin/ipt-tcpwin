IDIR = ../kernel
CFLAGS = -O2 -Wall -I$(IDIR)

all: libxt_TCPWIN.so

lib%.so: lib%.o
	${CC} -shared -fPIC -o $@ $^;

lib%.o: lib%.c
	${CC} -D_INIT=lib$*_init -fPIC ${CFLAGS} -o $@ -c $<

clean:
	rm -f *.{o,so}
