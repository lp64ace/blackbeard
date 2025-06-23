#include "MEM_guardedalloc.h"

#include <stdio.h>

const char *source = NULL;
const char *binary = NULL;

static inline void help(const char *program_name) {
	fprintf(stderr, "Invalid argument list!\n\n");
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\t%s --src <file> --bin <file>\n", program_name);
}

static inline bool init(int argc, char **argv) {
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--src") == 0 && i + 1 < argc) {
			source = argv[++i];
			continue;
		}
		if (strcmp(argv[i], "--bin") == 0 && i + 1 < argc) {
			binary = argv[++i];
			continue;
		}
		return false;  // Invalid argument
	}
	return source && binary;  // Return true only if both arguments are provided
}

static inline const char *strprev(const char *begin, const char *end, const char *itr, int c) {
	for (; begin <= itr && itr < end; itr--) {
		if (itr[0] == c) {
			return itr;
		}
	}
	return begin - 1;
}

int main(int argc, char **argv) {
#ifndef NDEBUG
	MEM_init_memleak_detection();
	MEM_enable_fail_on_memleak();
	MEM_use_guarded_allocator();
#endif

	long size;

	if (!init(argc, argv)) {
		help(argv[0]);
		return -1;
	}

	FILE *fpin;

	if (!(fpin = fopen(source, "rb"))) {
		fprintf(stderr, "Failed to open input <%s>\n", source);
		return -1;
	}

	fseek(fpin, 0L, SEEK_END);
	size = ftell(fpin);
	fseek(fpin, 0L, SEEK_SET);

	FILE *fpout;

	if (!(fpout = fopen(binary, "wb"))) {
		fprintf(stderr, "Failed to open output <%s>\n", binary);
		return -1;
	}

	size_t slength = strlen(source);

	const char *last = source, *now = NULL;
	if ((now = strprev(source, source + slength, source + slength - 1, '\\')) > last) {
		last = now + 1;
	}
	if ((now = strprev(source, source + slength, source + slength - 1, '/')) > last) {
		last = now + 1;
	}

	char *name = strdup(last);

	for (size_t i = 0; name[i] != '\0'; i++) {
		if (name[i] == '.') {
			name[i] = '_';
		}
	}

	fprintf(fpout, "/* DataToC output of file <%s> */\n\n", last);
	fprintf(fpout, "extern const int datatoc_%s_size;\n", name);
	fprintf(fpout, "extern const char datatoc_%s[];\n\n", name);

	fprintf(fpout, "const int datatoc_%s_size = %ld;\n", name, size);
	fprintf(fpout, "const char datatoc_%s[] = {\n\t", name);

	free(name);

	for (long index = 0; index <= size; index++) {
		if (index && index % 16 == 0) {
			fprintf(fpout, "\n\t");
		}
		if (index < size) {
			fprintf(fpout, "0x%02x, ", getc(fpin));
		}
		else {
			fprintf(fpout, "0");
		}
	}

	fprintf(fpout, "\n};\n");

	fclose(fpout);
	fclose(fpin);

	return 0;
}
