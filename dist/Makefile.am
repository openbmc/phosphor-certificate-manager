dbuspolicydir=@dbuspolicydir@
certmgrenvdir=$(datadir)/phosphor-certificate-manager
systemunitdir=$(rootprefix)/lib/systemd/system

certmgrenv_DATA =
SYSTEM_UNIT_ALIASES =
SYSTEM_UNIT_OVERRIDES =

systemunit_DATA = phosphor-certificate-manager@.service

if CA_CERT_EXTENSION
systemunit_DATA += bmc-vmi-ca-manager.service
endif

if ENABLE_BMCWEB_CERT_CONFIG
certmgrenv_DATA += env/bmcweb
SYSTEM_UNIT_OVERRIDES += phosphor-certificate-manager@bmcweb.service.d overrides/bmcweb.conf
SYSTEM_UNIT_ALIASES += \
	../phosphor-certificate-manager@.service multi-user.target.wants/phosphor-certificate-manager@bmcweb.service
endif

if ENABLE_NSLCD_CERT_CONFIG
certmgrenv_DATA += env/nslcd
SYSTEM_UNIT_ALIASES += \
	../phosphor-certificate-manager@.service multi-user.target.wants/phosphor-certificate-manager@nslcd.service
endif

if ENABLE_NSLCD_AUTHORITY_CERT_CONFIG
certmgrenv_DATA += env/authority
SYSTEM_UNIT_OVERRIDES += phosphor-certificate-manager@authority.service.d overrides/authority.conf
SYSTEM_UNIT_ALIASES += \
	../phosphor-certificate-manager@.service multi-user.target.wants/phosphor-certificate-manager@authority.service
endif

install-aliases-hook:
	set -- $(SYSTEM_UNIT_ALIASES) && \
	  dir=$(systemunitdir) && $(install-aliases)

install-overrides-hook:
	set -- $(SYSTEM_UNIT_OVERRIDES) && \
	  dir=$(systemunitdir) && $(install-overrides)

define install-aliases
  while [ -n "$$1" ]; do \
	$(MKDIR_P) `dirname $(DESTDIR)$$dir/$$2` && \
	rm -f $(DESTDIR)$$dir/$$2 && \
	$(LN_S) $(srcdir)/$$1 $(DESTDIR)$$dir/$$2 && \
	shift 2 || exit $$?; \
  done
endef

define install-overrides
  while [ -n "$$1" ]; do \
	$(MKDIR_P) $(DESTDIR)$$dir/$$1 && \
	rm -f $(DESTDIR)$$dir/$$1/`basename $$2` && \
	$(INSTALL) $(srcdir)/$$2 $(DESTDIR)$$dir/$$1/`basename $$2` && \
	shift 2 || exit $$?; \
  done
endef

INSTALL_DATA_HOOKS = \
	install-aliases-hook \
	install-overrides-hook

install-data-hook: $(INSTALL_DATA_HOOKS)
