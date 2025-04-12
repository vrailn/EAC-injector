#pragma once

extern "C" __int64 direct_device_control(
	HANDLE,
	HANDLE,
	PIO_APC_ROUTINE,
	PVOID,
	PIO_STATUS_BLOCK,
	std::uint32_t,
	PVOID,
	std::uint32_t,
	PVOID,
	std::uint32_t
);

namespace driver {
	enum class e_command_type : std::uint32_t {
		unload_driver,
		is_active,
		open_process,
		attach_process,
		detach_process,
		get_process_peb,
		read_memory,
		write_memory,
		get_eprocess,
		get_base_address,
		translate_linear,
		allocate_virtual,
		free_virtual,
		map_process_pte,
		map_physical,
		get_dtb
	};

	struct s_command_data {
		std::uint32_t m_pid{};
		std::uintptr_t m_address{};
		std::uintptr_t m_address2{};
		eprocess_t* m_process{};
		std::size_t m_size{};
		void* m_buffer{};
		peb_t* m_peb{};
		kapc_state_t m_apc_state{};
		NTSTATUS m_status{};
	};

	class c_command {
	public:
		c_command( ) = default;
		c_command(
			e_command_type type,
			s_command_data data,
			bool completed = false )
			: m_type( type ), m_data( data ), m_completed( completed ) {
		}

		bool is_completed( ) const { return m_completed; }
		void set_completed( bool state ) { m_completed = state; }

		NTSTATUS get_status( ) const { return get_data( ).m_status; }
		void set_status( NTSTATUS status_code ) const {
			auto data = get_data( );
			data.m_status = status_code;
		}

		e_command_type get_type( ) const { return m_type; }
		const s_command_data& get_data( ) const { return m_data; }

	private:
		e_command_type m_type;
		s_command_data m_data;
		bool m_completed;
		std::uint64_t m_timestamp;
	};
}