#include <impl/includes.h>

int __cdecl main( int argc, char** argv ) {
	if ( argc < 2 ) {
		logging::print( encrypt( "Error: Missing parameters" ) );
		logging::print( encrypt( "Press any key to exit..." ) );
		return std::getchar( );
	}

	SetConsoleTitleA( encrypt( "vware_injector" ) );

	if ( !g_driver->setup( ) )
		return std::getchar( );

	if ( !g_driver->is_active( ) ) {
		logging::print( encrypt( "Connection timed out, try again.\n" ) );
		g_driver->unload( );
		return std::getchar( );
	}

	if ( !g_driver->attach( target_process ) ) {
		logging::print( encrypt( "Failed to attach process.\n" ) );
		g_driver->unload( );
		return std::getchar( );
	}

	if ( !injector::manual_map( argv[ 1 ] ) ) {
		g_driver->unload( );
		return std::getchar( );
	}

	g_driver->unload( );
	return std::getchar( );
}