include $(top_srcdir)/Makefile.decl

SUBDIRS = \
	library \
	tools

ACLOCAL_AMFLAGS = -I m4

DISTCHECK_CONFIGURE_FLAGS = \
	--enable-gtk-doc \
	--disable-coverage

dist-hook:
	@if test -d "$(srcdir)/.git"; \
	then \
		echo Creating ChangeLog && \
		( cd "$(top_srcdir)" && \
		  echo '# Generate automatically. Do not edit.'; echo; \
		  $(top_srcdir)/missing --run git log --stat --date=short ) > ChangeLog.tmp \
		&& mv -f ChangeLog.tmp $(top_distdir)/ChangeLog \
		|| ( rm -f ChangeLog.tmp ; \
		     echo Failed to generate ChangeLog >&2 ); \
	else \
		echo A git clone is required to generate a ChangeLog >&2; \
	fi

if ENABLE_GTK_DOC
upload-doc: all
	rsync -Hvax --exclude doc \
		doc/html/./ anarchy.freedesktop.org:/srv/my-path/www/doc/adcli/./
endif

upload-release: $(DIST_ARCHIVES)
	gpg --detach-sign --local-user 'stef@thewalter.net' $(DIST_ARCHIVES)
	scp $(DIST_ARCHIVES) $(DIST_ARCHIVES).sig anarchy.freedesktop.org:/srv/my-path/www/releases/

EXTRA_DIST = config.rpath
