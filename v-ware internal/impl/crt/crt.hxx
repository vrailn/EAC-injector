#include <string>
#include <windows.h>

int __strcmp( const char* str1, const char* str2 ) {
    while ( *str1 && *str2 && *str1 == *str2 ) {
        ++str1;
        ++str2;
    }
    return static_cast< unsigned char >( *str1 ) - static_cast< unsigned char >( *str2 );
}

int __cdecl __wcsicmp( const wchar_t* str1, const wchar_t* str2 ) {
    while ( *str1 && *str2 ) {
        wchar_t c1 = ( *str1 >= L'A' && *str1 <= L'Z' ) ? *str1 + 32 : *str1;
        wchar_t c2 = ( *str2 >= L'A' && *str2 <= L'Z' ) ? *str2 + 32 : *str2;
        if ( c1 != c2 ) return c1 - c2;
        ++str1;
        ++str2;
    }
    return *str1 - *str2;
}

HMODULE GetModuleBase( const wchar_t* moduleName ) {
    PPEB peb = ( PPEB )__readgsqword( 0x60 );
    for ( PLIST_ENTRY entry = peb->Ldr->InMemoryOrderModuleList.Flink; entry != &peb->Ldr->InMemoryOrderModuleList; entry = entry->Flink ) {
        auto* moduleEntry = CONTAINING_RECORD( entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );
        const wchar_t* fullName = moduleEntry->FullDllName.Buffer;
        size_t fullLen = moduleEntry->FullDllName.Length / sizeof( wchar_t );
        size_t nameLen = wcslen( moduleName );

        if ( fullLen >= nameLen && __wcsicmp( fullName + fullLen - nameLen, moduleName ) == 0 ) {
            return ( HMODULE )moduleEntry->DllBase;
        }
    }
    return NULL;
}

FARPROC ManualGetProcAddress( HMODULE hModule, const char* functionName ) {
    if ( !hModule ) return NULL;

    auto dosHeader = ( PIMAGE_DOS_HEADER )hModule;
    auto ntHeaders = ( PIMAGE_NT_HEADERS )( ( BYTE* )hModule + dosHeader->e_lfanew );
    auto exportDir = ( PIMAGE_EXPORT_DIRECTORY )( ( BYTE* )hModule + ntHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );

    auto funcNames = ( DWORD* )( ( BYTE* )hModule + exportDir->AddressOfNames );
    auto funcOrdinals = ( WORD* )( ( BYTE* )hModule + exportDir->AddressOfNameOrdinals );
    auto funcAddresses = ( DWORD* )( ( BYTE* )hModule + exportDir->AddressOfFunctions );

    for ( DWORD i = 0; i < exportDir->NumberOfNames; i++ ) {
        if ( __strcmp( ( char* )hModule + funcNames[ i ], functionName ) == 0 ) {
            return ( FARPROC )( ( BYTE* )hModule + funcAddresses[ funcOrdinals[ i ] ] );
        }
    }
    return NULL;
}

template <typename T>
T rva_to_va( uintptr_t rva, PIMAGE_SECTION_HEADER sectionHeader, BYTE* targetImage, int numSections ) {
    for ( int i = 0; i < numSections; i++ ) {
        auto& section = sectionHeader[ i ];
        if ( rva >= section.VirtualAddress && rva < section.VirtualAddress + section.Misc.VirtualSize ) {
            return reinterpret_cast< T >( targetImage + section.PointerToRawData + rva - section.VirtualAddress );
        }
    }
    return nullptr;
}

void LoadModules( uintptr_t base ) {
    auto dosHeader = ( PIMAGE_DOS_HEADER )base;
    auto ntHeaders = ( PIMAGE_NT_HEADERS )( ( BYTE* )base + dosHeader->e_lfanew );
    auto sectionHeader = ( PIMAGE_SECTION_HEADER )( ( uintptr_t )( &ntHeaders->OptionalHeader ) + ntHeaders->FileHeader.SizeOfOptionalHeader );

    auto importDir = &ntHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
    if ( !importDir->VirtualAddress || !importDir->Size ) return;

    auto importDesc = rva_to_va<PIMAGE_IMPORT_DESCRIPTOR>( importDir->VirtualAddress, sectionHeader, ( BYTE* )base, ntHeaders->FileHeader.NumberOfSections );
    if ( !importDesc ) return;

    while ( importDesc->Name ) {
        auto moduleName = rva_to_va<char*>( importDesc->Name, sectionHeader, ( BYTE* )base, ntHeaders->FileHeader.NumberOfSections );
        if ( !moduleName ) break;

        std::wstring moduleNameW( moduleName, moduleName + strlen( moduleName ) );
        if ( !GetModuleBase( moduleNameW.c_str( ) ) ) {
            LoadLibraryA( moduleName );
        }

        ++importDesc;
    }
}