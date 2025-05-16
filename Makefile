
#CFLAGS := -I/usr/X11R6/include -I/usr/X11R6/include/freetype2 -ggdb3
#LDFLAGS := -L/usr/X11R6/lib -lxcb -lXau -lXdmcp -lfontconfig -lfreetype -lm

CFLAGS := -MMD -ggdb3 -I/usr/local/include
LDFLAGS := -L/usr/local/lib -lsqlite3

objs := gitkeeper.o log.o sha.o admin.o key.o repos.o
deps := $(objs:.o=.d)

gitkeeper: $(objs) schema.sql
	cc $(LDFLAGS) $(objs) -o $@

clean:
	rm $(objs) $(deps)
	rm gitkeeper

-include $(deps)