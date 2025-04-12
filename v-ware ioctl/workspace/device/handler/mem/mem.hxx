namespace handler {
    nt_status_t read_memory( user::s_command_data* input_data, size_t output_size, size_t* bytes_written ) {
        auto find_min = [ input_data ]( std::size_t size ) {
            return ( size < ( input_data->m_size ) ? ( size ) : ( input_data->m_size ) );
            };

        auto physical_address = mm::g_paging.translate( input_data->m_address );
        if ( !physical_address ) {
            *bytes_written = sizeof( user::c_command );
            return nt_status_t::unsuccessful;
        }

        auto final_size = find_min( mm::paging::page_4kb_size - ( physical_address & mm::paging::page_4kb_mask ) );
        auto result = mm::phys::read_direct(
            physical_address,
            input_data->m_buffer,
            final_size
        );

        *bytes_written = sizeof( user::c_command );
        return result;
    }

    nt_status_t write_memory( user::s_command_data* input_data, size_t input_size, size_t* bytes_written ) {
        auto find_min = [ input_data ]( std::size_t size ) {
            return ( size < ( input_data->m_size ) ? ( size ) : ( input_data->m_size ) );
            };

        auto physical_address = mm::g_paging.translate( input_data->m_address );
        if ( !physical_address ) {
            *bytes_written = sizeof( user::c_command );
            return nt_status_t::unsuccessful;
        }

        auto final_size = find_min( mm::paging::page_4kb_size - ( physical_address & mm::paging::page_4kb_mask ) );
        auto result = mm::phys::write_region(
            physical_address,
            input_data->m_buffer,
            final_size
        );

        *bytes_written = sizeof( user::c_command );
        return result ? nt_status_t::success : nt_status_t::unsuccessful;
    }

    nt_status_t translate_linear( user::s_command_data* input_data, size_t* bytes_written ) {
        std::uint32_t page_size = 0;
        input_data->m_address2 = mm::g_paging.translate( input_data->m_address, &page_size );
        input_data->m_size = static_cast< std::size_t >( page_size );

        *bytes_written = sizeof( user::c_command );
        return input_data->m_address2 ? nt_status_t::success : nt_status_t::unsuccessful;
    }

    nt_status_t map_process_pte( user::s_command_data* input_data, size_t* bytes_written ) {
        eac::c_module eac_module;
        if ( !eac_module.setup( ) ) {
            *bytes_written = sizeof( user::c_command );
            return nt_status_t::insufficient_resources;
        }

        kapc_state_t state{};
        if ( !eac_module.attach_process( input_data->m_process, &state ) ) {
            *bytes_written = sizeof( user::c_command );
            return nt_status_t::insufficient_resources;
        }

        if ( !mm::g_paging.map_process_pte( input_data->m_address ) ) {
            eac_module.detach_process( input_data->m_process, &state );
            *bytes_written = sizeof( user::c_command );
            return nt_status_t::access_violation;
        }

        eac_module.detach_process( input_data->m_process, &state );
        *bytes_written = sizeof( user::c_command );

        return input_data->m_address ? nt_status_t::success : nt_status_t::unsuccessful;
    }

    nt_status_t allocate_virtual( user::s_command_data* input_data, size_t* bytes_written ) {
        eac::c_module eac_module;
        if ( !eac_module.setup( ) ) {
            *bytes_written = sizeof( user::c_command );
            return nt_status_t::insufficient_resources;
        }

        kapc_state_t state{};
        if ( !eac_module.attach_process( input_data->m_process, &state ) ) {
            *bytes_written = sizeof( user::c_command );
            return nt_status_t::insufficient_resources;
        }

        if ( eac_module.allocate_memory( input_data->m_process, &input_data->m_address, &input_data->m_size, 0x00001000 | 0x00002000, 0x40 ) ) {
            eac_module.detach_process( input_data->m_process, &state );
            *bytes_written = sizeof( user::c_command );
            return nt_status_t::insufficient_resources;
        }

        if ( !eac_module.zero_memory( input_data->m_pid, reinterpret_cast< void* >( input_data->m_address ), input_data->m_size ) ) {
            eac_module.detach_process( input_data->m_process, &state );
            *bytes_written = sizeof( user::c_command );
            return nt_status_t::insufficient_resources;
        }

        if ( !mm::g_paging.map_process_pte( input_data->m_address ) ) {
            eac_module.detach_process( input_data->m_process, &state );
            *bytes_written = sizeof( user::c_command );
            return nt_status_t::access_violation;
        }

        eac_module.detach_process( input_data->m_process, &state );
        *bytes_written = sizeof( user::c_command );

        return input_data->m_address ? nt_status_t::success : nt_status_t::unsuccessful;
    }

    nt_status_t free_virtual( user::s_command_data* input_data, size_t* bytes_written ) {
        eac::c_module eac_module;
        if ( !eac_module.setup( ) ) {
            *bytes_written = sizeof( user::c_command );
            return nt_status_t::insufficient_resources;
        }

        if ( eac_module.free_memory( input_data->m_process, reinterpret_cast< void* >( input_data->m_address ), input_data->m_size ) ) {
            *bytes_written = sizeof( user::c_command );
            return nt_status_t::unsuccessful;
        }

        *bytes_written = sizeof( user::c_command );
        return nt_status_t::success;
    }

    nt_status_t map_physical( user::s_command_data* input_data, size_t* bytes_written ) {
        if ( !input_data->m_address || !input_data->m_size ) {
            *bytes_written = sizeof( user::c_command );
            return nt_status_t::invalid_parameter;
        }

        auto aligned_phys = mm::g_paging.page_align( input_data->m_address );
        auto page_offset = input_data->m_address - aligned_phys;

        auto total_size = mm::g_paging.page_align( input_data->m_size + page_offset );
        if ( total_size == 0 ) {
            total_size = mm::paging::page_4kb_size;
        }

        auto mapped_va = reinterpret_cast< std::uintptr_t >(
            nt::mm_map_io_space( aligned_phys, total_size )
            );

        if ( !mapped_va ) {
            *bytes_written = sizeof( user::c_command );
            return nt_status_t::unsuccessful;
        }

        input_data->m_address2 = mapped_va + page_offset;
        input_data->m_size = total_size;

        *bytes_written = sizeof( user::c_command );
        return nt_status_t::success;
    }
}