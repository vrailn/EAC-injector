#include <chrono>
#include <ctime>
#include <vector>
#include <Windows.h>
#include <tlhelp32.h>
#include <fstream>
#include <vector>
#include <winternl.h>
#include <cstdint>
#include <DbgHelp.h>
#include <thread>
#include <mutex>
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "ntdll.lib")
#define target_process L"RustClient.exe"

#include <dependencies/skcrypt/skcrypter.h>
#include <workspace/logger/logger.hxx>

#include <impl/ia32/ia32.h>
#include <impl/wdk/wdk.h>
#include <workspace/driver/driver.hxx>
auto g_driver = new driver::c_driver;

#include <impl/asmjit/core.h>
#include <impl/asmjit/a64.h>
#include <impl/asmjit/x86.h>

#include <workspace/injector/discord/discord.hxx>
#include <workspace/injector/shellcode/shellcode.h>
#include <workspace/injector/shellcode/compiler/compiler.hxx>
#include <workspace/injector/shellcode/internals/internals.hxx>
#include <workspace/injector/module/module.hxx>
#include <workspace/injector/injector.hxx>