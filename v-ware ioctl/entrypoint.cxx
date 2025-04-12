#include <impl/includes.h>

struct dpc_context {
	std::uint64_t image_base;
	std::uint64_t entry_point;
	std::uint32_t image_size;
	std::uint32_t status;
};

nt_status_t entry_point() {
    if (!nt::g_resolver.setup())
        return nt_status_t::not_supported;

    if (!mm::g_paging.setup())
        return nt_status_t::not_supported;

    nt::dbg_print("Hello from the driver!");

    device::init_ioctl_name();
    nt::create_driver(dispatch::intialize_driver);
}