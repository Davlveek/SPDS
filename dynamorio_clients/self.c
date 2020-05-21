#define _CRT_SECURE_NO_WARNINGS

#include "dr_api.h"
#include "drmgr.h"
#include "drwrap.h"
#include "drx.h"
#include "drcovlib.h"
#include <string.h>
#include <windows.h>

#define BUF_SIZE 64
#define INVALID_THREAD_ID 0

const char* path = "D:\\analysis\\";

file_t anti_debug_file, anti_VM_file;
const char* AntiDebug = "[AntiDebug].txt";
const char* AntiVM = "[AntiVM].txt";

file_t bb_file, trace_file;
const char* bb = "[bb].txt";
const char* trace = "[trace].txt";

char* exe_name;
static app_pc exe_start;

const char* good = "[GOOD]";
const char* bad = "[BAD]";

// Boolean vars for tricks
bool get_peb = false;
bool trap_flag = false;
bool seh = false;
bool isDebuggerPresent = false;
bool checkRemoteDebuggerPresent = false;
bool getVersionExA = false;
bool ntQueryInformationProcess = false;
bool getThreadContext = false;
bool ntSetInformationThread = false;
bool ntCreateThreadEx = false;

bool pills_commands = false;
bool malicious_commands = false;
bool env_check = false;

// For evasion Trap Flag
bool trap_flag_ev = false;
int jmp_count = 0;

static void event_exit(void);
dr_emit_flags_t new_block(void *drcontext, void *tag, instrlist_t *bb,
                          bool for_trace, bool translating);

dr_emit_flags_t new_trace(void *drcontext, void *tag, instrlist_t *trace,
						  bool translating);
static void event_module_load(void *drcontext, const module_data_t *info, bool loaded);
static void event_module_unload(void *drcontext, const module_data_t *info);

char* get_exe_name(char* full_path)
{
	char* current_name = strrchr(full_path, '\\');
	current_name++;
	char* temp = strstr(current_name, ".exe");
	temp[0] = '\0';
	return current_name;
}

char* form_filename(const char* s1, const char* s2)
{
	char* str = (char*)malloc(sizeof(char) * (strlen(s1) + strlen(s2) + 1)); 
	strcpy(str, s1);
	strcat(str, s2);
	return str;
}

DR_EXPORT void
dr_client_main(client_id_t id, int args, const char *argv[])
{
	module_data_t *exe;

    dr_set_client_name("Anti-Debug client", "http://dynamorio.org/issues");
	
	// Init extensions
	drmgr_init();
	drwrap_init();
	drx_init();
	
	// Register exit event
	dr_register_exit_event(event_exit);
	// Register event for basic block
	drmgr_register_bb_app2app_event(new_block, NULL);
	// Register trace event
	dr_register_trace_event(new_trace);
	// Register module load and unload events
	drmgr_register_module_load_event(event_module_load);
	drmgr_register_module_unload_event(event_module_unload);

	// Get executable data, name and starting address 
	exe = dr_get_main_module();
	exe_name = get_exe_name(exe->full_path);
	exe_start = exe->start;
	// Free executable data
	dr_free_module_data(exe);
	
	char* ex = (char*)malloc(sizeof(char) * (strlen(exe_name) + 1));
	strcpy(ex, exe_name);

	// Create anti-debug and anti-VM info files
	char* anti_debug_filename = form_filename(ex, AntiDebug);
	char* anti_debug_path = form_filename(path, anti_debug_filename);
	anti_debug_file = dr_open_file(anti_debug_path, DR_FILE_WRITE_APPEND);
	DR_ASSERT(anti_debug_file != INVALID_FILE);

	char* anti_VM_filename = form_filename(ex, AntiVM);
	char* anti_VM_path = form_filename(path, anti_VM_filename);
	anti_VM_file = dr_open_file(anti_VM_path, DR_FILE_WRITE_APPEND);
	DR_ASSERT(anti_VM_file != INVALID_FILE);

	// Create output disassemble file (bb)
	char* bb_filename = form_filename(ex, bb);
	char* bb_path = form_filename(path, bb_filename);
	bb_file = dr_open_file(bb_path, DR_FILE_WRITE_APPEND);
	DR_ASSERT(bb_file != INVALID_FILE);
	
	// Create output file for traces
	char* trace_filename = form_filename(ex, trace);
	char* trace_path = form_filename(path, trace_filename);
	trace_file = dr_open_file(trace_path, DR_FILE_WRITE_APPEND);
	DR_ASSERT(trace_file != INVALID_FILE);
	
	// Setting Intel asm syntax
	disassemble_set_syntax(DR_DISASM_INTEL);

	free(anti_debug_filename);
	free(anti_debug_path);
	free(anti_VM_filename);
	free(anti_VM_path);
	free(bb_filename);
	free(bb_path);
	free(trace_filename);
	free(trace_path);
	free(ex);
}

void instr_to_file(void *drcontext, instr_t *instr, file_t file)
{
	instr_disassemble(drcontext, instr, file);
	dr_write_file(file, "\n", 1);
}

void replace_jz_by_jmp(void *drcontext, instr_t *instr, instrlist_t *bb)
{
	opnd_t opnd = instr_get_src(instr, 0);
	instr_t *new_instr = INSTR_CREATE_jmp(drcontext, opnd);
	instr_set_translation(new_instr, instr_get_app_pc(instr));
	instrlist_replace(bb, instr, new_instr);
	instr_destroy(drcontext, instr);
}

void anti_debug_methods(void *drcontext, instr_t **instr, instrlist_t *bb)
{
	char buf[BUF_SIZE];

	instr_disassemble_to_buffer(drcontext, *instr, buf, BUF_SIZE);
	int opcode = instr_get_opcode(*instr);

	// Get PEB
	if (strstr(buf, "mov") != NULL)
	{
		if (strstr(buf, "dword ptr [fs:0x30]") != NULL) { get_peb = true; }
	}
	// Trap Flag
	if (opcode == OP_pushf) // in disasm is pushfd (same popfd)
	{
		*instr = instr_get_next(*instr);
		instr_disassemble_to_buffer(drcontext, *instr, buf, BUF_SIZE);
		opcode = instr_get_opcode(*instr);

		instr_to_file(drcontext, *instr, bb_file);

		if (opcode == OP_or)
		{
			if (strstr(buf, "dword ptr [esp], 0x00000100") != NULL)
			{
				*instr = instr_get_next(*instr);
				opcode = instr_get_opcode(*instr);
				instr_to_file(drcontext, *instr, bb_file);

				if (opcode == OP_popf) 
				{ 
					trap_flag = true;
					trap_flag_ev = true;
				}
			}
		}
	}
	// SEH
	if (strstr(buf, "push   dword ptr [fs:0x00]") != NULL)
	{
		*instr = instr_get_next(*instr);
		instr_disassemble_to_buffer(drcontext, *instr, buf, BUF_SIZE);
		if (strstr(buf, "mov    dword ptr [fs:0x00], esp") != NULL)
		{
			*instr = instr_get_next(*instr);
			opcode = instr_get_opcode(*instr);
			if (opcode == OP_int3) { seh = true; } 
		}
	}
}

void anti_VM_methods(void *drcontext, instr_t *instr)
{
	char buf[BUF_SIZE];

	instr_disassemble_to_buffer(drcontext, instr, buf, BUF_SIZE);
	int opcode = instr_get_opcode(instr);
	
	// Pills commands
	if (opcode == OP_sidt) { pills_commands = true; }
	else if (opcode == OP_sgdt) { pills_commands = true; }
	else if (opcode == OP_sldt) { pills_commands = true; }
	else if (opcode == OP_smsw) { pills_commands = true; }
	else if (opcode == OP_str) { pills_commands = true; }
	else if (strstr(buf, "in") != NULL) { pills_commands = true; }

	// Malicious commands
	else if (strstr(buf, "cmd") != NULL) { malicious_commands = true; }
	else if (strstr(buf, "cpuid") != NULL) { malicious_commands = true; }
	else if (strstr(buf, "autorun") != NULL) { malicious_commands = true; }
	else if (strstr(buf, "autorunsc") != NULL) { malicious_commands = true; }

	// Enviroment checking
	else if (strstr(buf, "dmesg") != NULL) { env_check = true; }
	else if (strstr(buf, "kmods") != NULL) { env_check = true; }
	else if (strstr(buf, "pcidevs") != NULL) { env_check = true; }
	else if (strstr(buf, "dmidecode") != NULL) { env_check = true; }
	else if (strstr(buf, "sysfs") != NULL) { env_check = true; }
	else if (strstr(buf, "procfs") != NULL) { env_check = true; }
	else if (strstr(buf, "dashXmstdout") != NULL) { env_check = true; }
}

dr_emit_flags_t new_block(void *drcontext, void *tag, instrlist_t *bb,
                          bool for_trace, bool translating)
{
	int opcode;

	// Iterate bb 
	instr_t *instr;
	for (instr = instrlist_first(bb); instr != NULL; instr = instr_get_next(instr)) 
	{
		opcode = instr_get_opcode(instr);
		instr_to_file(drcontext, instr, bb_file);

		// Evasion Trap Flag method 
		if (opcode == OP_jz && jmp_count == 2)
		{
			trap_flag_ev = false;
			jmp_count = 0;
			replace_jz_by_jmp(drcontext, instr, bb);
		}
		if (trap_flag_ev && opcode == OP_jmp)
			jmp_count++;

		// Check tricks
		anti_debug_methods(drcontext, &instr, bb);
		anti_VM_methods(drcontext, instr);
	}
	
	return DR_EMIT_DEFAULT;
}

dr_emit_flags_t new_trace(void *drcontext, void *tag, instrlist_t *trace,
						  bool translating)				  
{
	// Iterate instr trace
	instr_t *instr, *next;
	for (instr = instrlist_first(trace); instr != NULL; instr = next) 
	{
		instr_disassemble(drcontext, instr, trace_file);
		dr_write_file(trace_file, "\n", 1);
		
		next = instr_get_next(instr);
	}
	
	return DR_EMIT_DEFAULT;
}

bool nt_detect = false;
static void lib_entry(void *wrapcxt, INOUT void **user_data)
{
	const char *name = (const char *) *user_data;
	if (strstr(name, "IsDebuggerPresent") != NULL) { isDebuggerPresent = true; }
	if (strstr(name, "CheckRemoteDebuggerPresent") != NULL) 
	{ 
		checkRemoteDebuggerPresent = true; 
		bool ok = drwrap_skip_call(wrapcxt, NULL, 8);
		DR_ASSERT(ok);
	}
	if (strstr(name, "GetVersionExA") != NULL) { getVersionExA = true; }
	if (strstr(name, "NtQueryInformationProcess") != NULL) { ntQueryInformationProcess = true;	}
	if (strstr(name, "GetThreadContext") != NULL) { getThreadContext = true; }
	if (strstr(name, "LoadLibrary") != NULL)
	{
		char* lib = drwrap_get_arg(wrapcxt, 0);
		if (strstr(lib, "ntdll.dll") != NULL)
			nt_detect = true;
	}
	if (strstr(name, "GetProcAddress") != NULL && nt_detect)
	{
		char* func = drwrap_get_arg(wrapcxt, 1);
		if (strstr(func, "NtQueryInformationProcess") != NULL)
		{
			ntQueryInformationProcess = true;
			bool ok = drwrap_skip_call(wrapcxt, NULL, 1);
			DR_ASSERT(ok);
		}
		else if (strstr(func, "NtSetInformationThread") != NULL)
		{
			ntSetInformationThread = true; 
			bool ok = drwrap_skip_call(wrapcxt, NULL, 1);
			DR_ASSERT(ok);
		}
		else if (strstr(name, "NtCreateThreadEx") != NULL)
		{
			ntCreateThreadEx = true; 
			bool ok = drwrap_skip_call(wrapcxt, NULL, 1);
			DR_ASSERT(ok);
		}
	}
}

static void lib_final(void *wrapcxt, void *user_data)
{
	const char *name = (const char *)user_data;

	//dr_fprintf(anti_debug_file, "%s\n", name);

	if (strstr(name, "IsDebuggerPresent") != NULL) 
	{ 
		isDebuggerPresent = true; 
		bool ok = drwrap_set_retval(wrapcxt, (void*)1);
		DR_ASSERT(ok);
	}
	if (strstr(name, "NtQueryInformationProcess") != NULL) 
	{ 
		ntQueryInformationProcess = true; 
		bool ok = drwrap_set_retval(wrapcxt, (void*)1);
		DR_ASSERT(ok);
	}
}

static void iterate_exports(const module_data_t *info, bool add)
{
	dr_symbol_export_iterator_t *exp_iter = dr_symbol_export_iterator_start(info->handle);
 	while (dr_symbol_export_iterator_hasnext(exp_iter)) 
	{
    	dr_symbol_export_t *sym = dr_symbol_export_iterator_next(exp_iter);
        app_pc func = NULL;
        if (sym->is_code)
            func = sym->addr;
		
		if (func != NULL)
		{
			if (add)
			{
				drwrap_wrap_ex(func, lib_entry, lib_final, (void *) sym->name, 0);
			}	
			else 
			{
				drwrap_unwrap(func, lib_entry, NULL);
			}
		}
	}
	dr_symbol_export_iterator_stop(exp_iter);
}

static void event_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
	iterate_exports(info, true/*add*/);
}

static void event_module_unload(void *drcontext, const module_data_t *info)
{
	//iterate_exports(info, false/*remove*/);
}

void write_file_stats()
{
	dr_fprintf(anti_debug_file, "IsDebuggerPresent %s\n", isDebuggerPresent ? bad : good);
	dr_fprintf(anti_debug_file, "CheckRemoteDebuggerPresent %s\n", checkRemoteDebuggerPresent ? bad : good);
	dr_fprintf(anti_debug_file, "GetVersionExA %s\n", getVersionExA ? bad : good);
	dr_fprintf(anti_debug_file, "NtQueryInformationProcess %s\n", ntQueryInformationProcess ? bad : good);
	dr_fprintf(anti_debug_file, "GetThreadContext %s\n", getThreadContext ? bad : good);
	dr_fprintf(anti_debug_file, "NtSetInformationThread %s\n", ntSetInformationThread ? bad : good);
	dr_fprintf(anti_debug_file, "NtCreateThreadEx %s\n", ntCreateThreadEx ? bad : good);
	dr_fprintf(anti_debug_file, "Get PEB %s\n", get_peb ? bad : good);
	dr_fprintf(anti_debug_file, "TrapFlag %s\n", trap_flag ? bad : good);
	dr_fprintf(anti_debug_file, "SEH %s\n", seh ? bad : good);

	dr_fprintf(anti_VM_file, "Checking Pills commands %s\n", pills_commands ? bad : good);
	dr_fprintf(anti_VM_file, "Checking malicious commands %s\n", malicious_commands ? bad : good);
	dr_fprintf(anti_VM_file, "Checking Enviroment %s\n", env_check ? bad : good);
}

static void event_exit(void)
{
	write_file_stats();

	// Close files
	dr_close_file(bb_file);
	dr_close_file(trace_file);
	dr_close_file(anti_debug_file);
	dr_close_file(anti_VM_file);

	drx_exit();
    drwrap_exit();
    drmgr_exit();
}