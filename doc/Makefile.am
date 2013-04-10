include $(top_srcdir)/Makefile.decl

man8_MANS = \
	adcli.8 \
	$(NULL)

MAN_IN_FILES = \
	$(man8_MANS:.8=.xml)

DOCBOOK_FILE = adcli-docs.xml

CONTENT_INCLUDES = \
	adcli-devel.xml \
	$(NULL)

STATIC_FILES = \
	static/gtk-doc.css \
	static/style.css \
	$(NULL)

XSLT_FILES = \
	gtk-doc.xsl \
	version-greater-or-equal.xsl \
	$(NULL)

EXTRA_DIST = \
	$(DOCBOOK_FILE) \
	$(CONTENT_INCLUDES) \
	$(MAN_IN_FILES) \
	$(XSLT_FILES) \
	static \
	version.xml.in \
	version.xml \
	$(NULL)

CLEANFILES = \
	$(man8_MANS) \
	$(NULL)

XSLTPROC_FLAGS = \
	--nonet \
	--stringparam man.output.quietly 1 \
	--stringparam funcsynopsis.style ansi \
	--stringparam man.th.extra1.suppress 1 \
	--stringparam man.authors.section.enabled 0 \
	--stringparam man.copyright.section.enabled 0

XSLTPROC_MAN = \
	$(XSLTPROC) $(XSLTPROC_FLAGS) http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl

.xml.8:
	$(AM_V_GEN) $(XSLTPROC_MAN) $<

$(builddir)/html/index.html: $(DOCBOOK_FILE) $(CONTENT_INCLUDES) $(MAN_IN_FILES) $(STATIC_FILES)
	$(AM_V_GEN) mkdir -p $(builddir)/html && cp $(srcdir)/static/* $(builddir)/html/
	$(AM_V_GEN) $(XMLTO) html -m $(srcdir)/gtk-doc.xsl -o $(builddir)/html \
		--searchpath $(builddir):$(srcdir) $(srcdir)/$(DOCBOOK_FILE)

all-local: $(builddir)/html/index.html

clean-local:
	@rm -rf *.tmp $(builddir)/html

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(htmldir)
	$(INSTALL_DATA) $(builddir)/html/* $(DESTDIR)$(htmldir)

uninstall-local:
	rm -rf $(DESTDIR)$(htmldir)
