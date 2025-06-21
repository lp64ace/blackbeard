#include "memleak.h"
#include "MEM_guardedalloc.h"
#include "memusage.h"

#include <math.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

bool leak_detector_has_run = false;
char free_after_leak_detection_message[] =
	"Freeing memory after the leak detector has run. This can happen when "
	"using static variables in C++ that are defined outside of functions. "
	"To fix this error, use the 'construct on first use' idiom.";

namespace {

#ifndef NDEBUG
bool fail_on_memleak = true;
bool ignore_memleak = false;
#else
bool fail_on_memleak = false;
bool ignore_memleak = false;
#endif

class MemLeakPrinter {
public:
	~MemLeakPrinter() {
		if (ignore_memleak) {
			return;
		}
		leak_detector_has_run = true;
		size_t const leaked_blocks = MEM_num_memory_blocks_in_use();
		if (leaked_blocks == 0) {
			return;
		}
		size_t const leaked_memory = MEM_num_memory_in_use();
		fprintf(stderr, "[ERR] There are %zu not freed memory blocks.\n", leaked_blocks);

		char const *unit[] = {"B", "KB", "MB", "GB", "TB"};
		char const **iter = unit;

		double value = (double)leaked_memory;

		size_t const maxexp = sizeof(unit) / sizeof(unit[0]);
		while ((value / pow(1024, (double)(iter - unit))) > 1000 && (iter - unit) < (ptrdiff_t)maxexp) {
			iter++;
		}

		fprintf(stderr, "[ERR] Total unfreed memory %.3lf %s.\n", (value / pow(1024, (double)(iter - unit))), *iter);
		fflush(stderr);

		MEM_print_memlist();

		if (fail_on_memleak) {
			abort();
		}
	}
};

}  // namespace

void MEM_init_memleak_detection() {
	/* Calling this ensures that the memory usage counters outlive the memory leak
	 * detection. */
	memory_usage_init();

	/**
	 * This variable is constructed when this function is first called. This
	 * should happen as soon as possible when the program starts.
	 *
	 * It is destructed when the program exits. During destruction, it will print
	 * information about leaked memory blocks. Static variables are destructed in
	 * reversed order of their construction. Therefore, all static variables that
	 * own memory have to be constructed after this function has been called.
	 */
	static MemLeakPrinter printer;
}

void MEM_use_memleak_detection(bool enabled) {
	ignore_memleak = !enabled;
}

void MEM_enable_fail_on_memleak() {
	fail_on_memleak = true;
}
