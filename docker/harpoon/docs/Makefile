#
# $Id: Makefile.in,v 1.6 2005-12-07 17:07:00 jsommers Exp $
#

.SUFFIXES: .texi .pdf
srcdir = .


#############################################################################

SOURCES=harpoon_manual.texi intro.texi basic.texi \
	advanced.texi running.texi managing.texi appendices.texi
TARGET=harpoon_manual.dvi harpoon_manual.pdf

#############################################################################

all: $(TARGET)

html: harpoon_manual.html

install:
	@echo "there is no installation method with harpoon."

clean:
	rm -rf *~ harpoon_manual.vr harpoon_manual.tp harpoon_manual.pg harpoon_manual.ky harpoon_manual.fn harpoon_manual.cps harpoon_manual.toc harpoon_manual.cp harpoon_manual.aux harpoon_manual.log 

distclean: clean
	rm -f Makefile

.texi.pdf:
	texi2pdf $<

.texi.dvi:
	texi2dvi $<

.texi.html:
	texi2html $<

#############################################################################
# dependencies

harpoon_manual.dvi: $(SOURCES)
harpoon_manual.pdf: $(SOURCES)

