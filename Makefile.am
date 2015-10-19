include $(top_srcdir)/Makefile.decl

SUBDIRS = \
	build \
	library \
	tools

ACLOCAL_AMFLAGS = -I build/m4

DISTCHECK_CONFIGURE_FLAGS = \
	--disable-coverage \
	--enable-doc

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

upload-release: $(DIST_ARCHIVES)
	gpg --detach-sign --local-user 'stef@thewalter.net' $(DIST_ARCHIVES)
	scp $(DIST_ARCHIVES) $(DIST_ARCHIVES).sig anarchy.freedesktop.org:/srv/www.freedesktop.org/www/software/realmd/releases

memcheck:
	make -C library memcheck

leakcheck:
	make -C library leakcheck

if ENABLE_DOC
SUBDIRS += doc

upload-doc: all
	rsync -Hvax doc/html/./ anarchy.freedesktop.org:/srv/www.freedesktop.org/www/software/realmd/adcli/./

distcheck-hook:
	@true

else
upload-doc:
	@echo "*** doc must be enabled  (with --enable-doc) in order to make upload-doc"
	@false
distcheck-hook:
	@echo "*** doc must be enabled (with --enable-doc) in order to make distcheck"
	@false
endif
