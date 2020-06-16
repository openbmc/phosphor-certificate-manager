#include "config.h"

#include "hypervisor_cert_entry.hpp"

#include "hypervisor_certs_manager.hpp"

namespace ibm
{
namespace hypcert
{

void Entry::delete_()
{
    // Remove entry D-bus object
    manager.erase(id);
}
} // namespace hypcert
} // namespace ibm
