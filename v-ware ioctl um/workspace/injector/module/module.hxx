#include <map>

namespace module {
    class c_module {
    public:
        bool load_file( const std::string& file_path ) {
            std::ifstream file( file_path, std::ios::binary | std::ios::ate );
            if ( !file.is_open( ) ) {
                logging::print( encrypt( "Failed to open file: %s" ), file_path.c_str( ) );
                return false;
            }

            const auto file_size = file.tellg( );
            if ( file_size <= 0 ) {
                logging::print( encrypt( "Invalid file size: %s" ), file_path.c_str( ) );
                return false;
            }

            m_target_image.resize( static_cast< size_t >( file_size ) );

            file.seekg( 0, std::ios::beg );
            if ( !file.read( reinterpret_cast< char* >( m_target_image.data( ) ), file_size ) ) {
                logging::print( encrypt( "Failed to read file: %s" ), file_path.c_str( ) );
                m_target_image.clear( );
                return false;
            }

            m_dos_header = reinterpret_cast< PIMAGE_DOS_HEADER >( m_target_image.data( ) );
            if ( m_dos_header->e_magic != IMAGE_DOS_SIGNATURE ) {
                logging::print( encrypt( "Invalid DOS signature in: %s" ), file_path.c_str( ) );
                m_target_image.clear( );
                return false;
            }

            m_nt_headers = reinterpret_cast< PIMAGE_NT_HEADERS >(
                m_target_image.data( ) + m_dos_header->e_lfanew
                );
            if ( m_nt_headers->Signature != IMAGE_NT_SIGNATURE ) {
                logging::print( encrypt( "Invalid NT headers in: %s" ), file_path.c_str( ) );
                m_target_image.clear( );
                return false;
            }

            m_section_header = reinterpret_cast< IMAGE_SECTION_HEADER* >(
                ( std::uintptr_t )( &m_nt_headers->OptionalHeader ) + m_nt_headers->FileHeader.SizeOfOptionalHeader
                );

            m_optional_header = m_nt_headers->OptionalHeader;

            logging::print( encrypt( "Successfully loaded file: %s (Size: 0x%llX)" ),
                file_path.c_str( ), file_size );
            return true;
        }

        std::uint32_t get_image_size( ) const {
            return m_optional_header.SizeOfImage;
        }

        std::uint64_t get_entry_point( ) const {
            return m_optional_header.AddressOfEntryPoint;
        }

        std::uintptr_t get_export( LPCSTR module_name, LPCSTR function_name ) {
            auto module_handle = LoadLibraryExA( module_name, NULL, DONT_RESOLVE_DLL_REFERENCES );
            if ( !module_handle || module_handle == INVALID_HANDLE_VALUE ) {
                logging::print( encrypt( "Failed to load module: %s" ), module_name );
                return 0;
            }

            auto export_address = GetProcAddress( module_handle, function_name );
            if ( !export_address ) {
                logging::print( encrypt( "Failed to find export: %s!%s" ), module_name, function_name );
                FreeLibrary( module_handle );
                return 0;
            }

            auto offset = reinterpret_cast< std::uint64_t >( export_address ) - reinterpret_cast< std::uint64_t >( module_handle );
            FreeLibrary( module_handle );
            return offset;
        }

        bool is_dll( ) const {
            return ( m_nt_headers->FileHeader.Characteristics & IMAGE_FILE_DLL ) != 0;
        }

        std::uint64_t find_export( const char* export_name ) {
            auto export_dir = get_directory( IMAGE_DIRECTORY_ENTRY_EXPORT );
            if ( export_dir->VirtualAddress && export_dir->Size ) {
                auto export_directory = rva_to_va<PIMAGE_EXPORT_DIRECTORY>( export_dir->VirtualAddress );
                if ( export_directory ) {
                    auto functions = rva_to_va<DWORD*>( export_directory->AddressOfFunctions );
                    auto names = rva_to_va<DWORD*>( export_directory->AddressOfNames );
                    auto ordinals = rva_to_va<WORD*>( export_directory->AddressOfNameOrdinals );

                    if ( functions && names && ordinals ) {
                        for ( DWORD i = 0; i < export_directory->NumberOfNames; i++ ) {
                            auto name = rva_to_va<const char*>( names[ i ] );
                            if ( !name ) continue;

                            if ( !strcmp( name, export_name ) ) {
                                auto ordinal = ordinals[ i ];
                                return functions[ ordinal ];
                            }
                        }
                    }
                }
            }

            return 0;
        }

        uintptr_t resolve_func_addr( const char* module_name, const char* func_name ) {
            HMODULE module = GetModuleHandleA( module_name );
            if ( !module ) {
                module = LoadLibraryA( module_name );
                if ( !module ) return 0;
            }

            FARPROC proc_addr = GetProcAddress( module, func_name );
            if ( !proc_addr ) return 0;

            return ( uintptr_t )proc_addr - ( uintptr_t )module;
        }

        bool load_dependency( const wchar_t* path_name ) {
            std::string narrow_path;
            if ( !wide_to_narrow( path_name, narrow_path ) ) {
                logging::print( encrypt( "Path conversion failed" ) );
                return false;
            }

            auto pe_image = std::make_unique<module::c_module>( );
            if ( !pe_image->load_file( narrow_path.c_str( ) ) ) {
                logging::print( encrypt( "Failed to parse pe headers for dependency" ) );
                return false;
            }

            if ( !pe_image->is_dll( ) ) {
                logging::print( encrypt( "Dependency is not a dll" ) );
                return false;
            }

            auto image_size = pe_image->get_image_size( );
            auto image_va = g_driver->allocate_virtual( image_size );
            if ( !image_va ) {
                logging::print( encrypt( "Failed to allocate virtual memory for dependency" ) );
                g_driver->free_virtual( image_va );
                return false;
            }

            logging::print( encrypt( "Dependency allocated at: 0x%llx, Size=0x%x" ), image_va, image_size );

            if ( !pe_image->copy_headers( image_va ) ) {
                logging::print( encrypt( "Failed to write dependency headers" ) );
                g_driver->free_virtual( image_va );
                return false;
            }

            if ( !pe_image->map_sections( image_va ) ) {
                logging::print( encrypt( "Failed to write dependency sections" ) );
                g_driver->free_virtual( image_va );
                return false;
            }

            if ( !pe_image->relocate( image_va ) ) {
                logging::print( encrypt( "Failed to relocate dependency" ) );
                g_driver->free_virtual( image_va );
                return false;
            }

            //if ( !pe_image->map_imports( image_va ) ) {
            //    logging::print( encrypt( "Failed to map dependency imports" ) );
            //    g_driver->free_virtual( image_va );
            //    return false;
            //}

            auto export_rva = pe_image->find_export( encrypt( "DllMain" ) );
            if ( !export_rva ) {
                export_rva = pe_image->get_entry_point( );
                if ( !export_rva ) {
                    logging::print( encrypt( "No valid entry point found in dependency" ) );
                    g_driver->free_virtual( image_va );
                    return false;
                }
            }

            auto shellcode = std::make_unique<shellcode::c_shellcode>( image_va, export_rva );
            if ( !shellcode->setup( ) ) {
                logging::print( encrypt( "Failed to setup shellcode for dependency" ) );
                g_driver->free_virtual( image_va );
                return false;
            }

            if ( !shellcode->update( ) ) {
                logging::print( encrypt( "Failed to compile shellcode for dependency" ) );
                g_driver->free_virtual( image_va );
                return false;
            }

            if ( !shellcode->run( ) ) {
                logging::print( encrypt( "Failed to run shellcode for dependency" ) );
                g_driver->free_virtual( image_va );
                return false;
            }

            shellcode->cleanup( );
            logging::print( encrypt( "Successfully loaded dependency: %s" ), path_name );
            return true;
        }

        bool map_imports( std::uintptr_t target_base ) {
            auto import_dir = &m_nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
            if ( !import_dir->VirtualAddress || !import_dir->Size ) {
                logging::print( encrypt( "No imports to resolve" ) );
                return true;
            }

            auto import_desc = rva_to_va<PIMAGE_IMPORT_DESCRIPTOR>( import_dir->VirtualAddress );
            if ( !import_desc ) {
                logging::print( encrypt( "Invalid import descriptor" ) );
                return false;
            }

            size_t imports = 0;
            size_t modules = 0;

            while ( import_desc->Name ) {
                modules++;
                auto module_name = rva_to_va<const char*>( import_desc->Name );
                if ( !module_name ) {
                    logging::print( encrypt( "Invalid module name" ) );
                    return false;
                }

                std::string adjusted_module_name = module_name;
                bool is_debug_runtime = false;
                if ( _stricmp( module_name, "VCRUNTIME140D.dll" ) == 0 ) {
                    adjusted_module_name = "VCRUNTIME140.dll";
                    is_debug_runtime = true;
                    logging::print( encrypt( "Remapping debug runtime %s to %s" ),
                        module_name, adjusted_module_name.c_str( ) );
                }
                else if ( _stricmp( module_name, "ucrtbased.dll" ) == 0 ) {
                    adjusted_module_name = "ucrtbase.dll";
                    is_debug_runtime = true;
                    logging::print( encrypt( "Remapping debug runtime %s to %s" ),
                        module_name, adjusted_module_name.c_str( ) );
                }
                else if ( _stricmp( module_name, "MSVCP140D.dll" ) == 0 ) {
                    adjusted_module_name = "MSVCP140.dll";
                    is_debug_runtime = true;
                    logging::print( encrypt( "Remapping debug runtime %s to %s" ),
                        module_name, adjusted_module_name.c_str( ) );
                }

                auto module_handle = LoadLibraryA( adjusted_module_name.c_str( ) );
                if ( !module_handle ) {
                    logging::print( encrypt( "LoadLibrary failed for %s: %d" ),
                        adjusted_module_name.c_str( ), GetLastError( ) );
                    return false;
                }

                auto thunk_data = rva_to_va<PIMAGE_THUNK_DATA64>( import_desc->FirstThunk );
                auto original_thunk = import_desc->OriginalFirstThunk ?
                    rva_to_va<PIMAGE_THUNK_DATA64>( import_desc->OriginalFirstThunk ) :
                    thunk_data;

                for ( size_t i = 0; original_thunk[ i ].u1.AddressOfData != 0; i++ ) {
                    imports++;

                    uintptr_t func_addr = 0;
                    if ( IMAGE_SNAP_BY_ORDINAL64( original_thunk[ i ].u1.Ordinal ) ) {
                        WORD ordinal = IMAGE_ORDINAL64( original_thunk[ i ].u1.Ordinal );
                        auto func_name = reinterpret_cast< const char* >( static_cast< uintptr_t >( ordinal ) );

                        func_addr = ( uintptr_t )GetProcAddress( module_handle, ( LPCSTR )( ULONG_PTR )ordinal );
                        if ( !func_addr ) {
                            logging::print( encrypt( "GetProcAddress failed for ordinal %u: %d" ),
                                ordinal, GetLastError( ) );
                            FreeLibrary( module_handle );
                            return false;
                        }
                    }
                    else {
                        auto import_by_name = rva_to_va<PIMAGE_IMPORT_BY_NAME>( original_thunk[ i ].u1.AddressOfData );
                        if ( !import_by_name ) {
                            logging::print( encrypt( "Invalid import by name" ) );
                            FreeLibrary( module_handle );
                            return false;
                        }

                        auto func_name = import_by_name->Name;
                        func_addr = ( uintptr_t )GetProcAddress( module_handle, func_name );
                        if ( !func_addr ) {
                            logging::print( encrypt( "GetProcAddress failed for %s: %d" ),
                                func_name, GetLastError( ) );
                            FreeLibrary( module_handle );
                            return false;
                        }
                    }

                    thunk_data[ i ].u1.Function = func_addr;
                }

                FreeLibrary( module_handle );
                import_desc++;
            }

            auto iat_rva = m_nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IAT ].VirtualAddress;
            auto iat_size = m_nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IAT ].Size;
            if ( !iat_rva || !iat_size )
                return false;

            auto iat_data = rva_to_va<void*>( iat_rva );
            if ( !g_driver->write_memory( target_base + iat_rva, iat_data, iat_size ) ) {
                logging::print( encrypt( "Failed to write IAT to target process" ) );
                return false;
            }

            logging::print( encrypt( "Processed %zu imports from %zu modules" ), imports, modules );
            return true;
        }

        bool map_sections( std::uint64_t new_image_base ) {
            size_t total_bytes_written = 0;

            for ( auto i = 0u; i < m_nt_headers->FileHeader.NumberOfSections; i++ ) {
                const auto& section = m_section_header[ i ];
                if ( !section.VirtualAddress || !section.SizeOfRawData ) {
                    logging::print( encrypt( "Skipping section %s - Invalid parameters" ), section.Name );
                    continue;
                }

                auto section_va = new_image_base + section.VirtualAddress;
                if ( !section_va ) {
                    logging::print( encrypt( "Invalid section found at: %s" ), section.Name );
                    continue;
                }

                g_driver->write_memory(
                    section_va,
                    reinterpret_cast< void* >( m_target_image.data( ) + section.PointerToRawData ),
                    section.SizeOfRawData
                );

                total_bytes_written += section.SizeOfRawData;
                logging::print( encrypt( "Wrote section %-8s (0x%p -> 0x%p)" ),
                    section.Name, m_target_image.data( ) + section.PointerToRawData, section_va );
            }

            return true;
        }

        bool relocate( std::uint64_t new_image_base ) {
            auto reloc_dir = get_directory( IMAGE_DIRECTORY_ENTRY_BASERELOC );
            if ( !reloc_dir->VirtualAddress || !reloc_dir->Size ) {
                logging::print( encrypt( "No relocations needed" ) );
                return true;
            }

            auto delta = new_image_base - m_optional_header.ImageBase;
            if ( delta == 0 ) {
                logging::print( encrypt( "No relocation needed - Image loaded at preferred base address" ) );
                return true;
            }

            auto reloc_block = rva_to_va<PIMAGE_BASE_RELOCATION>( reloc_dir->VirtualAddress );
            auto reloc_end = reinterpret_cast< char* >( reloc_block ) + reloc_dir->Size;

            int block_count = 0;
            int reloc_count = 0;

            while ( reloc_block && reloc_block->VirtualAddress &&
                reinterpret_cast< char* >( reloc_block ) < reloc_end ) {

                block_count++;
                auto entry_count = ( reloc_block->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( WORD );
                auto entries = reinterpret_cast< WORD* >( reloc_block + 1 );

                for ( size_t i = 0; i < entry_count; i++ ) {
                    auto type = entries[ i ] >> 12;
                    auto offset = entries[ i ] & 0xFFF;
                    auto address = new_image_base + reloc_block->VirtualAddress + offset;

                    switch ( type ) {
                    case IMAGE_REL_BASED_ABSOLUTE:
                        break;

                    case IMAGE_REL_BASED_HIGH:
                    {
                        std::uint16_t value;
                        g_driver->read_memory( address, &value, sizeof( value ) );
                        value += static_cast< std::uint16_t >( ( delta >> 16 ) & 0xFFFF );
                        g_driver->write_memory( address, &value, sizeof( value ) );
                    }
                    break;

                    case IMAGE_REL_BASED_LOW:
                    {
                        std::uint16_t value;
                        g_driver->read_memory( address, &value, sizeof( value ) );
                        value += static_cast< std::uint16_t >( delta & 0xFFFF );
                        g_driver->write_memory( address, &value, sizeof( value ) );
                    }
                    break;

                    case IMAGE_REL_BASED_HIGHLOW:
                    {
                        std::uint32_t value;
                        g_driver->read_memory( address, &value, sizeof( value ) );
                        value += static_cast< std::uint32_t >( delta );
                        g_driver->write_memory( address, &value, sizeof( value ) );
                    }
                    break;

                    case IMAGE_REL_BASED_HIGHADJ:
                    {
                        std::uint16_t high_value;
                        g_driver->read_memory( address, &high_value, sizeof( high_value ) );

                        i++;
                        std::uint16_t low_value = entries[ i ];

                        std::uint32_t value = ( high_value << 16 ) | low_value;
                        value += static_cast< std::uint32_t >( delta );
                        value += 0x8000;

                        std::uint16_t new_high = static_cast< std::uint16_t >( value >> 16 );
                        g_driver->write_memory( address, &new_high, sizeof( new_high ) );
                    }
                    break;

                    case IMAGE_REL_BASED_DIR64: {
                        std::uint64_t value;
                        g_driver->read_memory( address, &value, sizeof( value ) );
                        value += delta;
                        g_driver->write_memory( address, &value, sizeof( value ) );
                    } break;

                    case IMAGE_REL_BASED_MIPS_JMPADDR:
                        logging::print( encrypt( "Warning: Unsupported relocation type IMAGE_REL_BASED_MIPS_JMPADDR" ) );
                        break;

                    case IMAGE_REL_BASED_MIPS_JMPADDR16:
                        logging::print( encrypt( "Warning: Unsupported relocation type IMAGE_REL_BASED_MIPS_JMPADDR16" ) );
                        break;

                    case IMAGE_REL_BASED_THUMB_MOV32:
                        logging::print( encrypt( "Warning: Unsupported relocation type IMAGE_REL_BASED_THUMB_MOV32" ) );
                        break;

                    default:
                        logging::print( encrypt( "Warning: Unknown relocation type %d" ), type );
                        break;
                    }

                    if ( type != IMAGE_REL_BASED_ABSOLUTE )
                        reloc_count++;
                }

                reloc_block = reinterpret_cast< PIMAGE_BASE_RELOCATION >(
                    reinterpret_cast< char* >( reloc_block ) + reloc_block->SizeOfBlock );
            }

            logging::print( encrypt( "Processed %d relocations" ), reloc_count );
            return true;
        }

        bool copy_headers( std::uintptr_t image_base ) {
            return g_driver->write_memory(
                image_base,
                m_target_image.data( ),
                m_optional_header.SizeOfHeaders 
            );
        }

        std::vector<uint8_t> get_target_image( ) {
            return m_target_image;
        }

    private:
        bool wide_to_narrow( const wchar_t* wide, std::string& narrow ) {
            int size = WideCharToMultiByte( CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr );
            if ( size == 0 ) return false;

            narrow.resize( size );
            return WideCharToMultiByte( CP_UTF8, 0, wide, -1, &narrow[ 0 ], size, nullptr, nullptr ) != 0;
        }

        PIMAGE_DOS_HEADER m_dos_header = nullptr;
        PIMAGE_NT_HEADERS64 m_nt_headers = nullptr;
        PIMAGE_SECTION_HEADER m_section_header = nullptr;
        IMAGE_OPTIONAL_HEADER64 m_optional_header{ };
        std::vector<uint8_t> m_target_image;
        size_t m_total_size = 0;

        IMAGE_SECTION_HEADER* find_section( const char* name ) {
            for ( WORD i = 0; i < m_nt_headers->FileHeader.NumberOfSections; i++ ) {
                auto& section = m_section_header[ i ];

                if ( memcmp( section.Name, name, strlen( name ) ) == 0 ) {
                    logging::print( encrypt( "Found section %s at index %d" ), name, i );
                    logging::print( encrypt( "Section details - VA: 0x%x, Size: 0x%x" ),
                        section.VirtualAddress,
                        section.SizeOfRawData );
                    return &m_section_header[ i ];
                }
            }

            logging::print( encrypt( "Section %s not found" ), name );
            return nullptr;
        }

        template <typename resut, typename type>
        resut rva_to_va( type rva ) {
            auto first_section = m_section_header;
            for ( auto section = first_section; section < first_section + m_nt_headers->FileHeader.NumberOfSections; section++ ) {
                if ( rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize )
                    return reinterpret_cast< resut >( m_target_image.data( ) + section->PointerToRawData + rva - section->VirtualAddress );
            }
            return reinterpret_cast< resut >( nullptr );
        }

        IMAGE_DATA_DIRECTORY* get_directory( int directory_index ) {
            if ( directory_index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES )
                return nullptr;

            return &m_nt_headers->OptionalHeader.DataDirectory[ directory_index ];
        }

        std::wstring string_to_wide( const std::string& narrow ) {
            if ( narrow.empty( ) ) return std::wstring( );

            const int buffer_size = MultiByteToWideChar( CP_UTF8, 0, narrow.c_str( ), -1, nullptr, 0 );
            if ( buffer_size == 0 ) return std::wstring( );

            std::wstring wide( buffer_size, 0 );
            if ( MultiByteToWideChar( CP_UTF8, 0, narrow.c_str( ), -1, &wide[ 0 ], buffer_size ) == 0 ) {
                return std::wstring( );
            }

            wide.resize( wcslen( wide.c_str( ) ) );
            return wide;
        }

        bool convert_to_wide( const char* narrow, std::wstring& wide ) {
            const int buffer_size = MultiByteToWideChar( CP_ACP, 0, narrow, -1, nullptr, 0 );
            if ( buffer_size == 0 ) return false;

            wide.resize( buffer_size );
            return MultiByteToWideChar( CP_ACP, 0, narrow, -1, &wide[ 0 ], buffer_size ) != 0;
        }

        bool is_api_set( const std::wstring& module_name ) {
            return module_name.find( L"api-ms-win" ) == 0;
        }

        bool resolve_api_set( const std::wstring& api_set_name, std::wstring& real_module ) {
            // Enhanced API set resolution
            static const std::map<std::wstring, std::wstring> api_set_map = {
                {L"api-ms-win-core", L"kernel32.dll"},
                {L"api-ms-win-security", L"advapi32.dll"},
                {L"api-ms-win-eventing", L"advapi32.dll"},
                {L"api-ms-win-rtcore", L"win32u.dll"},
                {L"api-ms-win-crt", L"ucrtbase.dll"},  // This will match api-ms-win-crt-runtime-l1-1-0.dll
                {L"api-ms-win-com", L"combase.dll"},
                {L"api-ms-win-power", L"powrprof.dll"}
            };

            // Special cases for specific API sets
            static const std::map<std::wstring, std::wstring> specific_api_sets = {
                {L"api-ms-win-crt-runtime-l1-1-0.dll", L"ucrtbase.dll"},
                {L"api-ms-win-crt-string-l1-1-0.dll", L"ucrtbase.dll"},
                {L"api-ms-win-crt-stdio-l1-1-0.dll", L"ucrtbase.dll"},
                {L"api-ms-win-crt-heap-l1-1-0.dll", L"ucrtbase.dll"},
                {L"api-ms-win-crt-math-l1-1-0.dll", L"ucrtbase.dll"},
                {L"api-ms-win-crt-locale-l1-1-0.dll", L"ucrtbase.dll"},
                {L"api-ms-win-crt-convert-l1-1-0.dll", L"ucrtbase.dll"},
                {L"api-ms-win-crt-time-l1-1-0.dll", L"ucrtbase.dll"},
                {L"api-ms-win-crt-filesystem-l1-1-0.dll", L"ucrtbase.dll"},
                {L"api-ms-win-crt-process-l1-1-0.dll", L"ucrtbase.dll"},
                {L"api-ms-win-crt-environment-l1-1-0.dll", L"ucrtbase.dll"}
            };

            // First check for exact matches
            auto it = specific_api_sets.find( api_set_name );
            if ( it != specific_api_sets.end( ) ) {
                real_module = it->second;
                logging::print( encrypt( "API set %S resolved to %S (exact match)" ),
                    api_set_name.c_str( ), real_module.c_str( ) );
                return true;
            }

            // Then try prefix matching
            std::wstring host_dll = L"kernelbase.dll";  // Default fallback

            for ( const auto& [prefix, dll] : api_set_map ) {
                if ( api_set_name.find( prefix ) == 0 ) {
                    host_dll = dll;
                    break;
                }
            }

            // Additional heuristics for specific API sets
            if ( host_dll == L"kernelbase.dll" ) {
                if ( api_set_name.find( L"memory" ) != std::wstring::npos ) host_dll = L"kernel32.dll";
                else if ( api_set_name.find( L"registry" ) != std::wstring::npos ) host_dll = L"advapi32.dll";
                else if ( api_set_name.find( L"file" ) != std::wstring::npos ) host_dll = L"kernelbase.dll";
            }

            real_module = host_dll;
            logging::print( encrypt( "API set %S resolved to %S (prefix match)" ),
                api_set_name.c_str( ), real_module.c_str( ) );

            if ( api_set_name.find( L"VCRUNTIME140D.dll" ) ) {
                logging::print( encrypt( "Remapping %ls to VCRUNTIME140.dll" ), api_set_name.c_str( ) );
                real_module = L"VCRUNTIME140.dll";
            }
            else if ( api_set_name.find( L"ucrtbased.dll" ) ) {
                logging::print( encrypt( "Remapping %ls to ucrtbase.dll" ), api_set_name.c_str( ) );
                real_module = L"ucrtbase.dll";
            }
            else if ( api_set_name.find( L"MSVCP140D.dll" ) ) {
                logging::print( encrypt( "Remapping %ls to MSVCP140.dll" ), api_set_name.c_str( ) );
                real_module = L"MSVCP140.dll";
            }

            return true;
        }

        bool locate_system_dependency( const std::wstring& module_name, std::wstring& path ) {
            wchar_t system_dir[ MAX_PATH ];
            if ( !GetSystemDirectoryW( system_dir, MAX_PATH ) ) {
                return false;
            }

            path = std::wstring( system_dir ) + L"\\" + module_name;

            if ( path.find( L'.' ) == std::wstring::npos ) {
                path += L".dll";
            }

            return GetFileAttributesW( path.c_str( ) ) != INVALID_FILE_ATTRIBUTES;
        }

        uintptr_t get_fallback_export( const char* module_name, const char* func_name ) {
            HMODULE hModule = LoadLibraryA( module_name );
            if ( !hModule ) {
                logging::print( encrypt( "LoadLibrary failed for %s: %d" ), module_name, GetLastError( ) );
                return 0;
            }

            uintptr_t func_addr = ( uintptr_t )GetProcAddress( hModule, func_name );
            if ( !func_addr ) {
                logging::print( encrypt( "GetProcAddress failed for %s: %d" ), func_name, GetLastError( ) );
                FreeLibrary( hModule );
                return 0;
            }

            uintptr_t offset = func_addr - ( uintptr_t )hModule;

            std::wstring module_string;
            if ( !convert_to_wide( module_name, module_string ) )
                return 0;

            uint64_t target_module_base = g_driver->get_process_module( module_string.c_str( ) );
            uintptr_t target_func_addr = target_module_base + offset;
            logging::print( encrypt( "Fallback resolved %s!%s at 0x%llx (offset: 0x%llx)" ),
                module_name, func_name, target_func_addr, offset );

            FreeLibrary( hModule );
            return target_func_addr;
        }

        uintptr_t get_module_export( uintptr_t module_base, const char* func_name ) {
            auto dos_header = g_driver->read<IMAGE_DOS_HEADER>( module_base );
            if ( dos_header.e_magic != IMAGE_DOS_SIGNATURE ) {
                logging::print( encrypt( "Invalid DOS header for module at 0x%llx" ), module_base );
                return 0;
            }

            auto nt_headers = g_driver->read<IMAGE_NT_HEADERS64>( module_base + dos_header.e_lfanew );
            if ( nt_headers.Signature != IMAGE_NT_SIGNATURE ) {
                logging::print( encrypt( "Invalid NT header for module at 0x%llx" ), module_base );
                return 0;
            }

            auto export_dir = nt_headers.OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];
            if ( !export_dir.VirtualAddress || !export_dir.Size ) {
                logging::print( encrypt( "No export directory for module at 0x%llx" ), module_base );
                return 0;
            }

            auto export_base = module_base + export_dir.VirtualAddress;
            auto exports = g_driver->read<IMAGE_EXPORT_DIRECTORY>( export_base );
            if ( exports.NumberOfFunctions == 0 || exports.NumberOfNames == 0 ||
                exports.AddressOfFunctions == 0 || exports.AddressOfNames == 0 || exports.AddressOfNameOrdinals == 0 ) {
                logging::print( encrypt( "Invalid export directory for module at 0x%llx" ), module_base );
                return 0;
            }

            auto names = g_driver->read_array<uint32_t>( module_base + exports.AddressOfNames,
                std::min<DWORD>( exports.NumberOfNames, 4096 ) );
            auto ordinals = g_driver->read_array<uint16_t>( module_base + exports.AddressOfNameOrdinals,
                std::min<DWORD>( exports.NumberOfNames, 4096 ) );
            auto functions = g_driver->read_array<uint32_t>( module_base + exports.AddressOfFunctions,
                std::min<DWORD>( exports.NumberOfFunctions, 4096 ) );

            for ( DWORD i = 0; i < exports.NumberOfNames && i < 4096; i++ ) {
                if ( names[ i ] == 0 ) continue;

                char name[ 256 ] = { 0 };
                if ( !g_driver->read_memory( module_base + names[ i ], name, sizeof( name ) - 1 ) ) {
                    continue;
                }

                if ( !name[ 0 ] || !isprint( name[ 0 ] ) ) continue;

                if ( strcmp( name, func_name ) == 0 ) {
                    if ( ordinals[ i ] >= exports.NumberOfFunctions ) {
                        logging::print( encrypt( "Invalid ordinal for %s" ), name );
                        continue;
                    }
                    return module_base + functions[ ordinals[ i ] ];
                }
            }

            logging::print( encrypt( "Export not found: %s in module at 0x%llx" ), func_name, module_base );
            return 0;
        }
    };
}