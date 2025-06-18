#include "mapper.h"
#include "module.h"
#include "native.h"
#include "process.h"
#include "remote.h"
#include "thread.h"

#include <stdio.h>
#include <tchar.h>

int main(void) {
	BOB_native_init();
	BobProcess *notepad;
	if ((notepad = BOB_process_open_by_name("notepad.exe"))) {
		fprintf(stdout, "notepad.exe\n");
		fprintf(stdout, "\tPID : %6d\n", BOB_process_identifier(notepad));
		
		BobThread *tmain = BOB_thread_open_by_process(notepad, THREAD_MAIN);
		BobThread *tmost = BOB_thread_open_by_process(notepad, THREAD_MOST);
		BobThread *tleast = BOB_thread_open_by_process(notepad, THREAD_LEAST);
		
		fprintf(stdout, "\tTHREADS\n");
		fprintf(stdout, "\t\tMAIN  : %6d | %.3lf\n", BOB_thread_identifier(tmain), BOB_thread_time_all(tmain));
		fprintf(stdout, "\t\tMOST  : %6d | %.3lf\n", BOB_thread_identifier(tmost), BOB_thread_time_all(tmost));
		fprintf(stdout, "\t\tLEAST : %6d | %.3lf\n", BOB_thread_identifier(tleast), BOB_thread_time_all(tleast));
		fprintf(stdout, "\tMODULES\n");
		fprintf(stdout, "\t\t%-16s  : 0x%p\n", "ntdll.dll", BOB_module_open_by_name(notepad, "ntdll.dll", SEARCH_LOADER));
		fprintf(stdout, "\t\t%-16s  : 0x%p\n", "kernel32.dll", BOB_module_open_by_name(notepad, "kernel32.dll", SEARCH_LOADER));
		
		BobModule *module = BOB_mapper_do(notepad, SOURCE_DIR L"/example.dll", NULL, 0);

		BOB_thread_close(tmain);
		BOB_thread_close(tmost);
		BOB_thread_close(tleast);

		BOB_process_close(notepad);
	}
	BOB_native_exit();
	return 0;
}
