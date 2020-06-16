#include "config.h"

#include "vmi_cert_entry.hpp"

#include "vmi_certs_manager.hpp"

namespace ibm
{
namespace vmicert
{

void Entry::delete_()
{
    // Remove entry D-bus object
    manager.erase(id);
}
} // namespace vmicert
} // namespace ibm
