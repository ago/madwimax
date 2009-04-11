# decide which pages to install
man_MANS = madwimax.8

# distribute the source in asciidoc format
EXTRA_DIST = madwimax.8.txt

madwimax.8.xml: $(srcdir)/madwimax.8.txt
	asciidoc -b docbook -d manpage -o $@ $<

madwimax.8: madwimax.8.xml
	xsltproc /usr/share/xml/docbook/stylesheet/nwalsh/manpages/docbook.xsl $<
