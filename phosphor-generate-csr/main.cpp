#include "config.h"

#include "generate_csr.hpp"

#include <sdbusplus/bus.hpp>

int main(int argc, char* argv[])
{
    auto bus = sdbusplus::bus::new_default();

    sdbusplus::server::manager::manager objManager(bus, CSR_OBJPATH);
    phosphor::certs::GenerateCSR csr(bus, CSR_OBJPATH);

    bus.request_name(CSR_BUSNAME);

    while (true)
    {
        bus.process_discard();
        bus.wait();
    }
    return 0;
}
