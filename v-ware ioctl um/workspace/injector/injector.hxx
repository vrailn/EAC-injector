
namespace injector {
    bool manual_map( const char* path_name ) {
        logging::print( encrypt( "Starting payload mapping process" ) );

        auto pe_image = std::make_unique<module::c_module>( );
        if ( !pe_image->load_file( path_name ) ) {
            logging::print( encrypt( "Failed to parse pe headers." ) );
            return false;
        }

        if ( !pe_image->is_dll( ) ) {
            logging::print( encrypt( "Image is not a dll or corrupted PE Headers." ) );
            return false;
        }

        auto image_size = pe_image->get_image_size( );
        auto image_va = g_driver->allocate_virtual( image_size );
        if ( !image_va ) {
            logging::print( encrypt( "Failed to allocate virtual memory." ) );
            g_driver->free_virtual( image_va );
            return false;
        }

        logging::print( encrypt( "PE allocated at: 0x%llx, Size=0x%x" ), image_va, image_size );

        if ( !pe_image->copy_headers( image_va ) ) {
            logging::print( encrypt( "Failed to write header" ) );
            g_driver->free_virtual( image_va );
            return false;
        }

        if ( !pe_image->map_sections( image_va ) ) {
            logging::print( encrypt( "Failed to write sections" ) );
            g_driver->free_virtual( image_va );
            return false;
        }

        if ( !pe_image->relocate( image_va ) ) {
            logging::print( encrypt( "Failed to relocate image" ) );
            g_driver->free_virtual( image_va );
            return false;
        }

        if ( !pe_image->map_imports( image_va ) ) {
            logging::print( encrypt( "Failed to map imports" ) );
            g_driver->free_virtual( image_va );
            return false;
        }

        auto export_rva = pe_image->find_export( encrypt( "DllMain" ) );
        if ( !export_rva ) {
            logging::print( encrypt( "Failed to DllMain RVA" ) );
            g_driver->free_virtual( image_va );
            return false;
        }

        logging::print( encrypt( "Module preparation completed successfully\n" ) );

        auto shellcode = std::make_unique<shellcode::c_shellcode>( image_va, export_rva );
        if ( !shellcode->setup( ) ) {
            logging::print( encrypt( "Failed to setup shellcode." ) );
            g_driver->free_virtual( image_va );
            return false;
        }

        if ( !shellcode->update( ) ) {
            logging::print( encrypt( "Failed to compile shellcode." ) );
            g_driver->free_virtual( image_va );
            return false;
        }

        if ( !shellcode->run( ) ) {
            logging::print( encrypt( "Failed to run shellcode." ) );
            g_driver->free_virtual( image_va );
            return false;
        }

        shellcode->cleanup( );
        return true;
    }
}