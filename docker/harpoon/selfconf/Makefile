#
# $Id: Makefile.in,v 1.7 2004-08-20 18:01:36 jsommers Exp $
#

srcdir = .


#############################################################################

TARGET=harpoon_flowproc
OBJS=harpoon_flowproc.o
all: harpoon_flowproc

CXX=g++
CPPFLAGS= -I../src
CXXFLAGS=-g -O2 -DBLOCKING_IO=0 -Wall -D_REENTRANT -DUSE_POLL=1 -fPIC
SHLIB_EXT=so
SHLIB_FLAG=-shared
LIBS=-lexpat -ldl -lz  -lpthread  -lz
LDFLAGS=

harpoon_flowproc: $(OBJS)
	$(CXX) -o $@ $(OBJS) $(LDFLAGS) $(LIBS)

clean:
	rm -rf $(TARGET) $(OBJS)

distclean: clean
	rm -f Makefile

.cc.o:
	$(CXX) -c $(CXXFLAGS) $(CPPFLAGS) $<

