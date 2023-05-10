#include "config.h"

#include "ca_cert_entry.hpp"

#include "ca_certs_manager.hpp"

namespace ca::cert
{

void Entry::delete_()
{
    // Remove entry D-bus object
    manager.erase(id);
}
} // namespace ca::cert
