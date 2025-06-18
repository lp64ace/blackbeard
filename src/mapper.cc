#include "config.h"
#include "list.h"
#include "mapper.h"
#include "module.h"
#include "native.h"
#include "process.h"
#include "thread.h"
#include "remote.h"

#include <tchar.h>

/* -------------------------------------------------------------------- */
/** \name Internal
 * \{ */

template<typename T> struct BobMapperArch;

template<> struct BobMapperArch<uint32_t> {
	using IMAGE_NT_HEADERS = IMAGE_NT_HEADERS32;
	using IMAGE_THUNK_DATA = IMAGE_THUNK_DATA32;
	using IMAGE_TLS_DIRECTORY = IMAGE_TLS_DIRECTORY32;
	using IMAGE_LOAD_CONFIG_DIRECTORY = IMAGE_LOAD_CONFIG_DIRECTORY32;
};

template<> struct BobMapperArch<uint64_t> {
	using IMAGE_NT_HEADERS = IMAGE_NT_HEADERS64;
	using IMAGE_THUNK_DATA = IMAGE_THUNK_DATA64;
	using IMAGE_TLS_DIRECTORY = IMAGE_TLS_DIRECTORY64;
	using IMAGE_LOAD_CONFIG_DIRECTORY = IMAGE_LOAD_CONFIG_DIRECTORY64;
};

template<typename T> class BobMapperImplementation : public BobMapperArch<T> {
	using IMAGE_NT_HEADERS = BobMapperArch<T>::IMAGE_NT_HEADERS;
	using IMAGE_THUNK_DATA = BobMapperArch<T>::IMAGE_THUNK_DATA;
	using IMAGE_TLS_DIRECTORY = BobMapperArch<T>::IMAGE_TLS_DIRECTORY;
	using IMAGE_LOAD_CONFIG_DIRECTORY = BobMapperArch<T>::IMAGE_LOAD_CONFIG_DIRECTORY;
	
protected:
	IMAGE_DOS_HEADER *dos;
	IMAGE_NT_HEADERS *nt;

	IMAGE_SECTION_HEADER *begin() {
		return static_cast<IMAGE_SECTION_HEADER *>(IMAGE_FIRST_SECTION(this->nt));
	}
	IMAGE_SECTION_HEADER *end() {
		return static_cast<IMAGE_SECTION_HEADER *>(IMAGE_FIRST_SECTION(this->nt) + this->nt->FileHeader.NumberOfSections);
	}
	
	bool is64() const {
		return this->nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
	}
	bool is32() const {
		return this->nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC;
	}
	
protected:
	enum {
		RVA,
		VA,
		RPA,
	};

	void *resolve_rva(void *base, uintptr_t rva, int type) {
		switch (type) {
			case RVA: {
				return reinterpret_cast<void *>(rva);
			} break;
			case VA: {
				for (IMAGE_SECTION_HEADER *section = this->begin(); section != this->end(); section++) {
					if (section->VirtualAddress <= rva && rva <= section->VirtualAddress + section->Misc.VirtualSize) {
						if (type == VA) {
							return POINTER_OFFSET(base, rva - section->VirtualAddress + section->PointerToRawData);
						} else {
							return POINTER_OFFSET(rva, section->VirtualAddress + section->PointerToRawData);
						}
					}
				}
			} break;
		}
		return NULL;
	}
	
	void *image_directory(void *base, int directory) {
		IMAGE_DATA_DIRECTORY *image = &this->nt->OptionalHeader.DataDirectory[directory];
		if (image->VirtualAddress == NULL || image->Size == 0) {
			return NULL;
		}
		return resolve_rva(base, image->VirtualAddress, VA);
	}
	
	size_t image_size(void *base, int directory) {
		IMAGE_DATA_DIRECTORY *image = &this->nt->OptionalHeader.DataDirectory[directory];
		if (image->VirtualAddress == NULL || image->Size == 0) {
			return 0;
		}
		return image->Size;
	}

	LPVOID find_activation_context_manifest(size_t *r_size);
	TCHAR *make_activation_context_manifest();
	HANDLE make_activation_context();
	NTSTATUS load_dependency_module(const wchar_t *fullpath);
	BobModule *find_dependency_module(const wchar_t *path, const char *modulename);
	BOOL thunk_is_ordinal(BobMapperImplementation<T>::IMAGE_THUNK_DATA *thunk);
	BOOL relocate(ptrdiff_t delta, WORD data, PBYTE base);
	BOOL write_section(IMAGE_SECTION_HEADER *section, int protection);

public:
	BobMapperImplementation(BobProcess *process, const wchar_t *path, const void *image, size_t size) : process(process) {
		this->source = static_cast<void *>(bobAlloc(size));
		memcpy(this->source, image, size);
		
		this->dos = static_cast<decltype(this->dos)>(this->source);
		this->nt = static_cast<decltype(this->nt)>(POINTER_OFFSET(this->dos, this->dos->e_lfanew));
		this->base = static_cast<T>(this->nt->OptionalHeader.ImageBase);
		this->size = static_cast<T>(this->nt->OptionalHeader.SizeOfImage);
		
		this->worker = BOB_remote_open(this->process);
	}
	
	~BobMapperImplementation() {
		BOB_remote_close(this->worker);
		bobFree(this->source);
	}
	
	bool map_imports(const wchar_t *path) {
		IMAGE_IMPORT_DESCRIPTOR *descriptor;
		if ((descriptor = static_cast<IMAGE_IMPORT_DESCRIPTOR *>(image_directory(this->source, IMAGE_DIRECTORY_ENTRY_IMPORT)))) {
			for (; descriptor->Name; descriptor++) {
				const char *modulename = static_cast<const char *>(resolve_rva(this->source, descriptor->Name, VA));
				if (!find_dependency_module(path, modulename)) {
					// return false;
				}
			}
		}

		if ((descriptor = static_cast<IMAGE_IMPORT_DESCRIPTOR *>(image_directory(this->source, IMAGE_DIRECTORY_ENTRY_IMPORT)))) {
			BobModule *module;

			for (; descriptor->Name; descriptor++) {
				const char *modulename = static_cast<const char *>(resolve_rva(this->source, descriptor->Name, VA));
				if (!(module = find_dependency_module(path, modulename))) {
					return false;
				}

				BobMapperImplementation::IMAGE_THUNK_DATA *thunk;
				BobMapperImplementation::IMAGE_THUNK_DATA *func;

				if (descriptor->OriginalFirstThunk) {
					thunk = static_cast<BobMapperImplementation::IMAGE_THUNK_DATA *>(resolve_rva(this->source, descriptor->OriginalFirstThunk, VA));
					func = static_cast<BobMapperImplementation::IMAGE_THUNK_DATA *>(resolve_rva(this->source, descriptor->FirstThunk, VA));
				} else {
					thunk = static_cast<BobMapperImplementation::IMAGE_THUNK_DATA *>(resolve_rva(this->source, descriptor->FirstThunk, VA));
					func = static_cast<BobMapperImplementation::IMAGE_THUNK_DATA *>(resolve_rva(this->source, descriptor->FirstThunk, VA));
				}

				for (; thunk->u1.AddressOfData; thunk++, func++) {
					FARPROC address = NULL;

					if (thunk_is_ordinal(thunk)) {
						WORD ordinal = thunk->u1.Ordinal & 0xFFFF;

						if (!(address = (FARPROC)BOB_module_export(this->process, module, reinterpret_cast<const char *>(ordinal)))) {
							return false;
						}
					} else {
						IMAGE_IMPORT_BY_NAME *named = static_cast<IMAGE_IMPORT_BY_NAME *>(resolve_rva(this->source, thunk->u1.AddressOfData, VA));

						if (!(address = (FARPROC)BOB_module_export(this->process, module, reinterpret_cast<const char *>(named->Name)))) {
							return false;
						}
					}

					func->u1.Function = reinterpret_cast<uintptr_t>(address);
				}
			}
		}

		return true;
	}

	bool map_imports_delayed(const wchar_t *path) {
		IMAGE_DELAYLOAD_DESCRIPTOR *descriptor;
		if ((descriptor = static_cast<IMAGE_DELAYLOAD_DESCRIPTOR *>(image_directory(this->source, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)))) {
			for (; descriptor->DllNameRVA; descriptor++) {
				const char *modulename = static_cast<const char *>(resolve_rva(this->source, descriptor->DllNameRVA, VA));
				if (!find_dependency_module(path, modulename)) {
					// return false;
				}
			}
		}

		if ((descriptor = static_cast<IMAGE_DELAYLOAD_DESCRIPTOR *>(image_directory(this->source, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)))) {
			BobModule *module;

			for (; descriptor->DllNameRVA; descriptor++) {
				const char *modulename = static_cast<const char *>(resolve_rva(this->source, descriptor->DllNameRVA, VA));
				if (!(module = find_dependency_module(path, modulename))) {
					return false;
				}

				BobMapperImplementation::IMAGE_THUNK_DATA *thunk;
				BobMapperImplementation::IMAGE_THUNK_DATA *func;

				thunk = static_cast<BobMapperImplementation::IMAGE_THUNK_DATA *>(resolve_rva(this->source, descriptor->ImportNameTableRVA, VA));
				func = static_cast<BobMapperImplementation::IMAGE_THUNK_DATA *>(resolve_rva(this->source, descriptor->ImportAddressTableRVA, VA));

				for (; thunk->u1.AddressOfData; thunk++, func++) {
					FARPROC address = NULL;

					if (thunk_is_ordinal(thunk)) {
						WORD ordinal = thunk->u1.Ordinal & 0xFFFF;

						if (!(address = (FARPROC)BOB_module_export(this->process, module, reinterpret_cast<const char *>(ordinal)))) {
							return false;
						}
					} else {
						IMAGE_IMPORT_BY_NAME *named = static_cast<IMAGE_IMPORT_BY_NAME *>(resolve_rva(this->source, thunk->u1.AddressOfData, VA));

						if (!(address = (FARPROC)BOB_module_export(this->process, module, reinterpret_cast<const char *>(named->Name)))) {
							return false;
						}
					}

					func->u1.Function = reinterpret_cast<uintptr_t>(address);
				}
			}
		}

		return true;
	}

	bool map_relocations() {
		if (this->nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) {
			return true;
		}

		ptrdiff_t delta = reinterpret_cast<ptrdiff_t>(this->remote) - static_cast<ptrdiff_t>(this->nt->OptionalHeader.ImageBase);

		IMAGE_BASE_RELOCATION *itr;
		DWORD size = image_size(this->source, IMAGE_DIRECTORY_ENTRY_BASERELOC);
		
		if ((itr = static_cast<IMAGE_BASE_RELOCATION *>(image_directory(this->source, IMAGE_DIRECTORY_ENTRY_BASERELOC)))) {
			PVOID end = POINTER_OFFSET(itr, size);

			while (itr < end) {
				PBYTE base = static_cast<PBYTE>(resolve_rva(this->source, itr->VirtualAddress, VA));
				DWORD nrelocations = (itr->SizeOfBlock - 8) / sizeof(WORD);
				PWORD data = static_cast<PWORD>(POINTER_OFFSET(itr, sizeof(IMAGE_BASE_RELOCATION)));

				for (DWORD i = 0; i < nrelocations; i++, data++) {
					if (!relocate(delta, *data, base)) {
						return false;
					}
				}

				itr = static_cast<IMAGE_BASE_RELOCATION *>(POINTER_OFFSET(itr, itr->SizeOfBlock));
			}
		}

		return true;
	}

	bool map_sections() {
		if (!BOB_process_write(this->process, this->remote, this->source, this->nt->OptionalHeader.SizeOfHeaders)) {
			return false;
		}

		for (IMAGE_SECTION_HEADER *section = this->begin(); section != this->end(); section++) {
			if (STREQ(reinterpret_cast<const char *>(section->Name), ".reloc")) {
				continue;
			}
			if (section->Characteristics & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)) {
				int protection = 0;
				if ((section->Characteristics & IMAGE_SCN_MEM_READ) != 0) {
					protection |= PROTECT_R;
				}
				if ((section->Characteristics & IMAGE_SCN_MEM_WRITE) != 0) {
					protection |= PROTECT_W;
				}
				if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
					protection |= PROTECT_E;
				}
				if (!write_section(section, protection)) {
					return false;
				}
			}
		}

		return true;
	}

	bool map_exceptions() {
		IMAGE_RUNTIME_FUNCTION_ENTRY *exptable = static_cast<IMAGE_RUNTIME_FUNCTION_ENTRY *>(image_directory(this->source, IMAGE_DIRECTORY_ENTRY_EXCEPTION));
		if (exptable) {
			BobModule *ntdll = BOB_module_open_by_name(this->process, "ntdll.dll", SEARCH_LOADER);

			void *address = POINTER_OFFSET(exptable, reinterpret_cast<ptrdiff_t>(this->remote) - reinterpret_cast<ptrdiff_t>(this->source));
			size_t length = image_size(this->source, IMAGE_DIRECTORY_ENTRY_EXCEPTION) / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);

			BOB_remote_begin64(this->worker);
			BOB_remote_push(this->worker, reinterpret_cast<uint64_t>(address), NODEREF);
			BOB_remote_push(this->worker, length, NODEREF);
			BOB_remote_push(this->worker, reinterpret_cast<uint64_t>(this->remote), NODEREF);
			BOB_remote_call(this->worker, BOB_module_export(this->process, ntdll, "RtlAddFunctionTable"));
			BOB_remote_save(this->worker, 0);
			BOB_remote_notify(this->worker);
			BOB_remote_end64(this->worker);

			if (!BOB_remote_invoke(this->worker, NULL)) {
				return false;
			}
		}
		return true;
	}

	bool map_entry(FARPROC entry) {
		if (this->is64()) {
			BobModule *kernel32 = BOB_module_open_by_name(this->process, "kernel32.dll", SEARCH_DEFAULT);

			BOB_remote_begin64(this->worker);

			BOB_remote_push(this->worker, (uint64_t)this->activation_context_handle, NODEREF);
			void *Cookie = BOB_remote_push_ex(this->worker, NULL, sizeof(ULONG_PTR));
			BOB_remote_call(this->worker, BOB_module_export(this->process, kernel32, "ActivateActCtx"));
			BOB_remote_save(this->worker, 1);
			// BOB_remote_breakpoint(this->worker);
			BOB_remote_push(this->worker, reinterpret_cast<uint64_t>(this->remote), NODEREF);
			BOB_remote_push(this->worker, DLL_PROCESS_ATTACH, NODEREF);
			BOB_remote_push(this->worker, 0, NODEREF);
			BOB_remote_call(this->worker, static_cast<void *>(entry));
			BOB_remote_save(this->worker, 0);
			// BOB_remote_breakpoint(this->worker);
			BOB_remote_push(this->worker, 0, NODEREF);
			BOB_remote_push(this->worker, reinterpret_cast<uint64_t>(Cookie), DEREFIMM64);
			BOB_remote_call(this->worker, BOB_module_export(this->process, kernel32, "DeactivateActCtx"));
			BOB_remote_save(this->worker, 2);

			BOB_remote_notify(this->worker);
			BOB_remote_end64(this->worker);

			if (!BOB_remote_invoke(this->worker, NULL)) {
				// DllMain returned FALSE!
			}

			return true;
		}

		BOB_remote_push(this->worker, reinterpret_cast<uint64_t>(this->remote), NODEREF);
		BOB_remote_push(this->worker, DLL_PROCESS_ATTACH, NODEREF);
		BOB_remote_push(this->worker, 0, NODEREF);
		BOB_remote_save(this->worker, 0);
		BOB_remote_notify(this->worker);

		if (!BOB_remote_invoke(this->worker, NULL)) {
			// DllMain returned FALSE!
		}

		return true;
	}

	bool map_tls() {
		BobMapperImplementation<T>::IMAGE_TLS_DIRECTORY *tls = static_cast<decltype(tls)>(image_directory(this->source, IMAGE_DIRECTORY_ENTRY_TLS));
		if (tls == NULL || tls->AddressOfCallBacks == NULL) {
			return true;
		}

		PIMAGE_TLS_CALLBACK callbacks[0xFF];
		if (!BOB_process_read(this->process, reinterpret_cast<void *>(tls->AddressOfCallBacks), callbacks, sizeof(callbacks))) {
			return false;
		}

		for (size_t i = 0; i < ARRAYSIZE(callbacks) && callbacks[i]; i++) {
			if (!map_entry((FARPROC)callbacks[i])) {
				return false;
			}
		}

		return true;
	}

	bool map_cookie() {
		BobMapperImplementation<T>::IMAGE_LOAD_CONFIG_DIRECTORY *config = static_cast<decltype(config)>(image_directory(this->source, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG));
		if (config == NULL || config->SecurityCookie == NULL) {
			return true;
		}

		FILETIME time = {};
		LARGE_INTEGER perfomance = {{}};

		uintptr_t cookie = 0;

		GetSystemTimeAsFileTime(&time);
		QueryPerformanceCounter(&perfomance);

		cookie = BOB_process_identifier(this->process) ^ BOB_thread_identifier(BOB_remote_thread(this->worker)) ^ reinterpret_cast<uintptr_t>(&cookie);

		if (this->is64()) {
			cookie ^= *reinterpret_cast<uintptr_t *>(&time);
			cookie ^= (perfomance.QuadPart << 32) ^ perfomance.QuadPart;
			cookie &= 0xFFFFFFFFFFFF;

			if (cookie == 0x2B992DDFA232) {
				cookie++;
			}
		}
		if (this->is32()) {
			cookie ^= time.dwHighDateTime ^ time.dwLowDateTime;
			cookie ^= perfomance.LowPart;
			cookie ^= perfomance.HighPart;

			if (cookie == 0xBB40E64E) {
				cookie++;
			} else if (!(cookie & 0xFFFF0000)) {
				cookie |= (cookie | 0x4711) << 16;
			}
		}

		void *address = POINTER_OFFSET(config->SecurityCookie, 0); // Handled by relocations already!
		if (!BOB_process_write(this->process, address, &cookie, sizeof(cookie))) {
			return false;
		}

		return true;
	}

	BobModule *map(const wchar_t *path) {
		uint64_t lo = 0x7FFFFFFFFFFFFFFF;
		uint64_t hi = 0x0000000000000000;
		for (auto section = this->begin(); section < this->end(); section++) {
			lo = min(lo, section->VirtualAddress);
			hi = max(hi, section->VirtualAddress + section->Misc.VirtualSize);
		}

		this->size = static_cast<T>(hi - lo);
		if (!(this->remote = BOB_process_alloc(this->process, reinterpret_cast<void *>(this->base), this->size, 0xFF))) {
			if (!(this->remote = BOB_process_alloc(this->process, reinterpret_cast<void *>(NULL), this->size, 0xFF))) {
				return NULL;
			}
		}

		if (this->is64()) {
			if (!(this->activation_context_handle = this->make_activation_context())) {
				return NULL;
			}
		}

		if (!map_imports(path)) {
			return NULL;
		}
		if (!map_imports_delayed(path)) {
			return NULL;
		}
		if (!map_relocations()) {
			return NULL;
		}
		if (!map_sections()) {
			return NULL;
		}
		if (this->is64()) {
			if (!map_exceptions()) {
				return NULL;
			}
		}
		if (!map_tls()) {
			return NULL;
		}
		if (!map_cookie()) {
			return NULL;
		}

		FARPROC entry = (FARPROC)POINTER_OFFSET(this->remote, this->nt->OptionalHeader.AddressOfEntryPoint);
		if (!map_entry(entry)) {
			return NULL;
		}
		
		return static_cast<BobModule *>(this->remote);
	}

private:
	BobProcess *process;
	BobRemote *worker;
	
	T base;
	T size;
	
	void *source;
	void *manifest;
	void *remote;
	
	HANDLE activation_context_handle;
};

template<typename T> LPVOID BobMapperImplementation<T>::find_activation_context_manifest(size_t *r_size) {
	if (!this->image_size(this->source, IMAGE_DIRECTORY_ENTRY_RESOURCE) || !this->image_directory(this->source, IMAGE_DIRECTORY_ENTRY_RESOURCE)) {
		return NULL;
	}

	void *resource = this->image_directory(this->source, IMAGE_DIRECTORY_ENTRY_RESOURCE);

	IMAGE_RESOURCE_DIRECTORY *root = static_cast<IMAGE_RESOURCE_DIRECTORY *>(resource);
	uintptr_t rootoffset = sizeof(IMAGE_RESOURCE_DIRECTORY);

	for (size_t i = 0; i < root->NumberOfIdEntries + root->NumberOfNamedEntries; i++) {
		IMAGE_RESOURCE_DIRECTORY_ENTRY *entry = static_cast<IMAGE_RESOURCE_DIRECTORY_ENTRY *>(POINTER_OFFSET(resource, rootoffset));

		if (entry->DataIsDirectory == NULL || entry->Id != 0x18) {
			rootoffset += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
			continue;
		}

		IMAGE_RESOURCE_DIRECTORY *directory = static_cast<IMAGE_RESOURCE_DIRECTORY *>(POINTER_OFFSET(resource, entry->OffsetToDirectory));
		uintptr_t diroffset = entry->OffsetToDirectory + sizeof(IMAGE_RESOURCE_DIRECTORY);
		for (size_t j = 0; j < directory->NumberOfIdEntries + directory->NumberOfNamedEntries; j++) {
			IMAGE_RESOURCE_DIRECTORY_ENTRY *item = static_cast<IMAGE_RESOURCE_DIRECTORY_ENTRY *>(POINTER_OFFSET(resource, diroffset));

			if (item->DataIsDirectory == NULL || (item->Id != 1 && item->Id != 2 && item->Id != 3)) {
				diroffset += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
				continue;
			}

			uintptr_t langoffset = item->OffsetToDirectory + sizeof(IMAGE_RESOURCE_DIRECTORY);
			IMAGE_RESOURCE_DIRECTORY_ENTRY *lang = static_cast<IMAGE_RESOURCE_DIRECTORY_ENTRY *>(POINTER_OFFSET(resource, langoffset));
			IMAGE_RESOURCE_DATA_ENTRY *data = static_cast<IMAGE_RESOURCE_DATA_ENTRY *>(POINTER_OFFSET(resource, lang->OffsetToData));

			if (r_size) {
				*r_size = data->Size;
			}

			return resolve_rva(this->source, data->OffsetToData, VA);
		}
	}

	return NULL;
}

template<typename T> TCHAR *BobMapperImplementation<T>::make_activation_context_manifest() {
	size_t size;

	LPVOID manifest;
	if ((manifest = this->find_activation_context_manifest(&size))) {
		TCHAR directory[MAX_PATH], filename[MAX_PATH];
		GetTempPath(ARRAYSIZE(directory), directory);
		if (GetTempFileName(directory, _T("ImageManifest"), 0, filename) == 0) {
			return NULL;
		}

		HANDLE fpout = CreateFile(filename, FILE_GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, 0, NULL);
		if (!fpout) {
			return NULL;
		}
		DWORD write;
		if (!WriteFile(fpout, manifest, size, &write, NULL)) {
			// return NULL;
		}
		CloseHandle(fpout);

		return (TCHAR *)BOB_remote_write(this->worker, filename, sizeof(filename));
	}

	return NULL;
}

template<typename T> HANDLE BobMapperImplementation<T>::make_activation_context() {
	TCHAR *source;
	if ((source = this->make_activation_context_manifest())) {
		ACTCTX context;
		memset(&context, 0, sizeof(ACTCTX));
		context.cbSize = sizeof(ACTCTX);
		context.lpSource = source;

		BobModule *kernel32 = BOB_module_open_by_name(this->process, "kernel32.dll", SEARCH_DEFAULT);

		BOB_remote_begin64(this->worker);
		BOB_remote_push_ex(this->worker, &context, sizeof(context));
		BOB_remote_call(this->worker, BOB_module_export(this->process, kernel32, STRINGIFY_DEFINE(CreateActCtx)));
		BOB_remote_save(this->worker, 0);
		BOB_remote_notify(this->worker);
		BOB_remote_end64(this->worker);

		return (HANDLE)BOB_remote_invoke(this->worker, NULL);
	}
	return NULL;
}

template<typename T> NTSTATUS BobMapperImplementation<T>::load_dependency_module(const wchar_t *fullpath) {
	BobModule *ntdll = BOB_module_open_by_name(this->process, "ntdll.dll", SEARCH_DEFAULT);

	if (this->is64()) {
		BOB_remote_begin64(this->worker);
	}

	// RtlInitUnicodeString
	void *UnicodeString = BOB_remote_push_ex(this->worker, NULL, sizeof(UNICODE_STRING));
	BOB_remote_push_wide(this->worker, fullpath);
	BOB_remote_call(this->worker, BOB_module_export(this->process, ntdll, "RtlInitUnicodeString"));

	// LdrLoadDll
	BOB_remote_push(this->worker, NULL, NODEREF);
	BOB_remote_push(this->worker, 0, NODEREF);
	BOB_remote_push(this->worker, reinterpret_cast<uint64_t>(UnicodeString), NODEREF);
	BOB_remote_push_ex(this->worker, NULL, sizeof(HMODULE));
	BOB_remote_call(this->worker, BOB_module_export(this->process, ntdll, "LdrLoadDll"));
	BOB_remote_save(this->worker, 0);

	BOB_remote_notify(this->worker);
	if (this->is64()) {
		BOB_remote_end64(this->worker);
	}

	return (NTSTATUS)BOB_remote_invoke(this->worker, NULL);
}

template<typename T> BobModule *BobMapperImplementation<T>::find_dependency_module(const wchar_t *path, const char *modulename) {
	BobModule *module = BOB_module_open_by_name(this->process, modulename, SEARCH_DEFAULT);

	if (!module) {
		WCHAR wname[MAX_PATH];
		WCHAR wpath[MAX_PATH];
		MultiByteToWideChar(CP_ACP, 0, modulename, -1, wname, ARRAYSIZE(wname));
		if (SearchPathW(NULL, wname, NULL, MAX_PATH, wpath, NULL)) {
			if (NT_SUCCESS(load_dependency_module(wpath))) {
				module = BOB_module_open_by_name(this->process, modulename, SEARCH_DEFAULT);
			}
		}
	}

	return module;
}

template<typename T> BOOL BobMapperImplementation<T>::thunk_is_ordinal(BobMapperImplementation<T>::IMAGE_THUNK_DATA *thunk) {
	if (this->is64()) {
		return thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64 != 0;
	}
	if (this->is32()) {
		return thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32 != 0;
	}
	return false;
}

#ifndef IMR_RELTYPE
#	define IMR_RELTYPE(x) ((x >> 12) & 0xF)
#endif

#ifndef IMR_RELOFFSET
#	define IMR_RELOFFSET(x) (x & 0xFFF)
#endif

template<typename T> BOOL BobMapperImplementation<T>::relocate(ptrdiff_t delta, WORD data, PBYTE base) {
	switch (IMR_RELTYPE(data)) {
		case IMAGE_REL_BASED_HIGH: {
			SHORT *raw = (SHORT *)(base + IMR_RELOFFSET(data));
			SHORT backup = *raw;

			*raw += (ULONG)HIWORD(delta);
		} return true;
		case IMAGE_REL_BASED_LOW: {
			SHORT *raw = (SHORT *)(base + IMR_RELOFFSET(data));
			SHORT backup = *raw;

			*raw += (ULONG)LOWORD(delta);
		} return true;
		case IMAGE_REL_BASED_HIGHLOW: {
			SIZE_T *raw = (SIZE_T *)(base + IMR_RELOFFSET(data));
			SIZE_T backup = *raw;

			*raw += (SIZE_T)delta;
		} return true;
		case IMAGE_REL_BASED_DIR64: {
			DWORD_PTR UNALIGNED *raw = (DWORD_PTR UNALIGNED *)(base + IMR_RELOFFSET(data));
			DWORD_PTR UNALIGNED backup = *raw;

			*raw += delta;
		} return true;
		case IMAGE_REL_BASED_ABSOLUTE: {
			// No relocation needed, this is an absolute address.
		} return true;
		case IMAGE_REL_BASED_HIGHADJ: {
			// This is a high adjustment, we need to adjust the next relocation.
		} return true;
	}
	return false;
}

template<typename T> BOOL BobMapperImplementation<T>::write_section(IMAGE_SECTION_HEADER *section, int protection) {
	if (!BOB_process_write(this->process, POINTER_OFFSET(this->remote, section->VirtualAddress), POINTER_OFFSET(this->source, section->PointerToRawData), section->SizeOfRawData)) {
		return false;
	}

	if (!BOB_process_protect(this->process, POINTER_OFFSET(this->remote, section->VirtualAddress), section->Misc.VirtualSize, protection)) {
		return false;
	}

	return true;
}

/** \} */

/* -------------------------------------------------------------------- */
/** \name Implementation
 * \{ */

static void *bob_mapper_read(const wchar_t *path, const void **r_image, size_t *r_size) {
	HANDLE fpin = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fpin == INVALID_HANDLE_VALUE) {
		return NULL;
	}

	DWORD size = GetFileSize(fpin, NULL);
	if (size == INVALID_FILE_SIZE || size == 0) {
		CloseHandle(fpin);
		return NULL;
	}

	void *buffer = static_cast<void *>(bobAlloc(size));
	if (buffer == NULL) {
		CloseHandle(fpin);
		return NULL;
	}

	DWORD read = 0;
	if (!ReadFile(fpin, buffer, size, &read, NULL)) {
		CloseHandle(fpin);
		bobFree(buffer);
		return NULL;
	}

	if (r_image) {
		*r_image = buffer;
	}
	if (r_size) {
		*r_size = size;
	}

	CloseHandle(fpin);
	return buffer;
}

BobModule *BOB_mapper_do(BobProcess *process, const wchar_t *path, const void *image, size_t size) {
	void *source = (image == NULL) ? bob_mapper_read(path, &image, &size) : NULL;

	BobModule *mapped = NULL;

	do {
		IMAGE_DOS_HEADER *dos = static_cast<IMAGE_DOS_HEADER *>(const_cast<void *>(image));
		if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) {
			break;
		}

		IMAGE_NT_HEADERS *nt = static_cast<IMAGE_NT_HEADERS *>(POINTER_OFFSET(dos, dos->e_lfanew));
		if (nt->Signature != IMAGE_NT_SIGNATURE) {
			break;
		}

		IMAGE_NT_HEADERS32 *nt32 = static_cast<IMAGE_NT_HEADERS32 *>(POINTER_OFFSET(dos, dos->e_lfanew));
		if (nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
			BobMapperImplementation<uint32_t> self(process, path, image, size);
			mapped = self.map(path);
			break;
		}

		IMAGE_NT_HEADERS64 *nt64 = static_cast<IMAGE_NT_HEADERS64 *>(POINTER_OFFSET(dos, dos->e_lfanew));
		if (nt64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
			BobMapperImplementation<uint64_t> self(process, path, image, size);
			mapped = self.map(path);
			break;
		}

		BobMapperImplementation<uintptr_t> self(process, path, image, size);
		mapped = self.map(path);
	} while (false);

	if (source) {
		bobFree(source);
	}

	return mapped;
}
 
/** \} */
