certmgrenvdir=$(datadir)/phosphor-certificate-manager

dbuspolicy_DATA =
certmgrenv_DATA =
SYSTEM_UNIT_ALIASES =

systemdsystemunit_DATA = phosphor-certificate-manager@.service

if CA_CERT_EXTENSION
dbuspolicy_DATA += busconfig/bmc-vmi-ca.conf
systemdsystemunit_DATA += bmc-vmi-ca-manager.service
endif

if ENABLE_BMCWEB_CERT_CONFIG
dbuspolicy_DATA += busconfig/phosphor-bmcweb-cert-config.conf
certmgrenv_DATA += env/bmcweb
SYSTEM_UNIT_ALIASES += \
	../phosphor-certificate-manager@.service multi-user.target.wants/phosphor-certificate-manager@bmcweb.service
endif

if ENABLE_NSLCD_AUTHORITY_CERT_CONFIG
dbuspolicy_DATA += busconfig/phosphor-nslcd-authority-cert-config.conf
certmgrenv_DATA += env/authority
SYSTEM_UNIT_ALIASES += \
	../phosphor-certificate-manager@.service multi-user.target.wants/phosphor-certificate-manager@authority.service
endif

install-aliases-hook:
	set -- $(SYSTEM_UNIT_ALIASES) && \
	  dir=$(systemdsystemunitdir) && $(install-aliases)

define install-aliases
  while [ -n "$$1" ]; do \
	$(MKDIR_P) `dirname $(DESTDIR)$$dir/$$2` && \
	rm -f $(DESTDIR)$$dir/$$2 && \
	$(LN_S) $$1 $(DESTDIR)$$dir/$$2 && \
	shift 2 || exit $$?; \
  done
endef

INSTALL_DATA_HOOKS = \
	install-aliases-hook

install-data-hook: $(INSTALL_DATA_HOOKS)
