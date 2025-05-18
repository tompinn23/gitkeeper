
#CFLAGS := -I/usr/X11R6/include -I/usr/X11R6/include/freetype2 -ggdb3
#LDFLAGS := -L/usr/X11R6/lib -lxcb -lXau -lXdmcp -lfontconfig -lfreetype -lm

CFLAGS := -MMD -ggdb3 -I/usr/local/include -I.
LDFLAGS := -L/usr/local/lib -lsqlite3

objs := gk.o log.o db/ro.o db/rw.o sha.o util.o
deps := $(objs:.o=.d)

gk: $(objs) schema.sql
	cc $(LDFLAGS) $(objs) -o $@

.c.o:
	cc $(CFLAGS) -c -o $@ $<

clean:
	rm $(objs) $(deps)
	rm gk

-include $(deps)
