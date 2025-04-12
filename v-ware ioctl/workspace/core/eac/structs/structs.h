#pragma once

namespace eac {
    struct control_t {
        void* m_control_type;
    };

    struct allocate_control_t : public control_t {
        void* m_address;
        unsigned __int64 m_zero_bits;
        unsigned __int64 m_region_size;
        unsigned int m_allocation_type;
        unsigned int m_protect;
    };

    struct free_control_t : public control_t {
        void* m_address;
        unsigned __int64 m_region_size;
        unsigned int m_free_type;
    };
}