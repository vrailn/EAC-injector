#include <windows.h>
#include <winternl.h>
#include <impl/crt/crt.hxx>
#include <intrin.h>

typedef HMODULE( WINAPI* LoadLibraryA_t )( LPCSTR );