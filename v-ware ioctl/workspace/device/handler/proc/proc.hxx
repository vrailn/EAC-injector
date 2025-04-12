namespace handler {
    nt_status_t get_eprocess( user::s_command_data* input_data, size_t* bytes_written ) {
        input_data->m_process = mm::process::find_process_by_id( input_data->m_pid );

        *bytes_written = sizeof( user::c_command );
        return input_data->m_process ? nt_status_t::success : nt_status_t::unsuccessful;
    }

    nt_status_t get_peb( user::s_command_data* input_data, size_t* bytes_written ) {
        input_data->m_peb = nt::get_process_peb( input_data->m_process );

        *bytes_written = sizeof( user::c_command );
        return input_data->m_peb ? nt_status_t::success : nt_status_t::unsuccessful;
    }

    nt_status_t get_base_address( user::s_command_data* input_data, size_t* bytes_written ) {
        input_data->m_address = reinterpret_cast< std::uintptr_t >(
            nt::ps_get_process_section_base_address( input_data->m_process )
            );

        *bytes_written = sizeof( user::c_command );
        return input_data->m_address ? nt_status_t::success : nt_status_t::unsuccessful;
    }

    nt_status_t open_process( user::s_command_data* input_data, size_t* bytes_written ) {
        if ( !input_data->m_pid ) {
            *bytes_written = sizeof( user::c_command );
            return nt_status_t::invalid_parameter;
        }

        client_id_t client_id = {};
        client_id.m_unique_process = reinterpret_cast< void* >( static_cast< std::uintptr_t >( input_data->m_pid ) );

        object_attributes_t object_attributes = {};
        nt::init_object_attributes( &object_attributes, nullptr, 0, nullptr, nullptr );

        void* process_handle = nullptr;
        auto status = nt::zw_open_process(
            &process_handle,
            0x1FFFFF,
            &object_attributes,
            &client_id
        );

        if ( status == nt_status_t::success && process_handle ) {
            input_data->m_buffer = process_handle;
            *bytes_written = sizeof( user::c_command );
            return nt_status_t::success;
        }

        *bytes_written = sizeof( user::c_command );
        return status;
    }

    nt_status_t attach_process( user::s_command_data* input_data, size_t* bytes_written ) {
        eac::c_module eac_module;
        if ( !eac_module.setup( ) ) {
            *bytes_written = sizeof( user::c_command );
            return nt_status_t::insufficient_resources;
        }

        if ( !eac_module.attach_process( input_data->m_process, &input_data->m_apc_state ) ) {
            *bytes_written = sizeof( user::c_command );
            return nt_status_t::unsuccessful;
        }

        *bytes_written = sizeof( user::c_command );
        return nt_status_t::success;
    }

    nt_status_t detach_process( user::s_command_data* input_data, size_t* bytes_written ) {
        eac::c_module eac_module;
        if ( !eac_module.setup( ) ) {
            *bytes_written = sizeof( user::c_command );
            return nt_status_t::insufficient_resources;
        }

        eac_module.detach_process( input_data->m_process, &input_data->m_apc_state );

        *bytes_written = sizeof( user::c_command );
        return nt_status_t::success;
    }

    nt_status_t get_dtb( user::s_command_data* input_data, size_t* bytes_written ) {
        if ( !mm::g_paging.scan_pages( input_data->m_address ) )
            return nt_status_t::unsuccessful;

        input_data->m_address2 = mm::g_paging.get_dtb( );
        *bytes_written = sizeof( user::c_command );
        return nt_status_t::success;
    }
}