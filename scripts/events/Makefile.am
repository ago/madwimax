if WITH_SCRIPT

eventsdir = $(sysconfdir)/madwimax
events_SCRIPTS = event.sh

event.sh: event.sh.$(script)
	cp event.sh.$(script) event.sh

MOSTLYCLEANFILES = event.sh
DISTCLEANFILES = event.sh.$(script)
EXTRA_DIST = event.sh.generic.in event.sh.wl500g.in

endif

