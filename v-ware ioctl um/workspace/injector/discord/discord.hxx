namespace discord {
	class c_discord {
	public:
		bool setup( ) {
			this->m_discord_hook64 = g_driver->get_process_module( encrypt( L"DiscordHook64.dll" ) );
			if ( !m_discord_hook64 ) {
				logging::print( encrypt( "Please enable discord overlay and try again." ) );
				return false;
			}

			return true;
		}

		std::uint64_t get_swap_chain( ) const {
			return g_driver->read( m_discord_hook64 + 0x10B520 );
		}

		std::uint64_t get_d3d12_context( ) const {
			return g_driver->read( m_discord_hook64 + 0x10B7A8 );
		}

		int get_api_flag( ) const {
			return g_driver->read<int>( m_discord_hook64 + 0x10B518 );
		}

		std::uintptr_t get_vtable( std::uint64_t ptr, int index ) const {
			return ptr + sizeof( std::uint64_t ) * index;
		}

	private:
		std::uint64_t m_discord_hook64 = 0;
		std::uint64_t m_swap_chain = 0;
		std::uint64_t m_d3d12_context = 0;
		std::uint64_t m_command_queue = 0;
		int m_api_flag = 0;
	};
}