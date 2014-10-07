#!/bin/sh -e

set -e

srcdir=$(dirname $0)
test -z "$srcdir" && srcdir=.

origdir=$(pwd)
cd $srcdir

# Some boiler plate to get git setup as expected
if test -d .git; then
	if test -f .git/hooks/pre-commit.sample && \
	   test ! -f .git/hooks/pre-commit; then
		cp -pv .git/hooks/pre-commit.sample .git/hooks/pre-commit
	fi
fi

set -x

autoreconf --force --install --verbose
if test x"$NOCONFIGURE" = x; then
  cd $origdir
  exec $srcdir/configure "$@"
fi

