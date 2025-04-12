#include <impl/includes.h>
#include <pplwin.h>

unsigned __stdcall entry_point( void* ) {
    MessageBoxA( NULL, "v-ware injector", "v-ware injector", NULL );
    return 0;
}

volatile LONG g_initialized = 0;
extern "C" __declspec( dllexport ) BOOL APIENTRY DllMain( HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
) {
    switch ( ul_reason_for_call ) {
    case DLL_PROCESS_ATTACH: {
        if ( InterlockedCompareExchange( &g_initialized, 1, 0 ) != 0 ) {
            return TRUE;
        }

        auto handle = _beginthreadex( 0, 0, entry_point, 0, 0, 0 );
        CloseHandle( reinterpret_cast< HANDLE >( handle ) );
    } break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return 1;
}