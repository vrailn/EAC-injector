namespace handler {
    nt_status_t is_active( user::s_command_data* input_data, size_t* bytes_written ) {
        *bytes_written = sizeof( user::c_command );
        return nt_status_t::success;
    }

    nt_status_t unload_driver( user::s_command_data* input_data, size_t* bytes_written ) {
        auto unload_work_item = reinterpret_cast< work_queue_item_t* >(
            nt::ex_allocate_pool( sizeof( work_queue_item_t ) )
            );

        if ( unload_work_item ) {
            nt::ex_init_work_item( unload_work_item, [ ]( void* context ) {
                unicode_string_t driver_name;
                nt::rtl_init_unicode_string( &driver_name, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\i-am-ioctl" );
                nt::zw_unload_driver( &driver_name );

                nt::ex_free_pool( context );
                }, unload_work_item );

            nt::ex_queue_work_item( unload_work_item, 1 );
        }

        *bytes_written = sizeof( user::c_command );
        return nt_status_t::success;
    }
}