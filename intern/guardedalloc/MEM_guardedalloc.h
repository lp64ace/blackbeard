#ifndef MEM_GUARDEDALLOC_H
#define MEM_GUARDEDALLOC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/**
 *
 * \file
 *
 * \page MEMPage Memory Allocator Module
 *
 * This is a memory allocator module, this was created for tracking and tackling
 * memory problems. Such memory problems include the following;
 *
 *  - Double free.
 *  - Out of bounds writes.
 *  - Memory leaks.
 *
 * These all introduce extra time complexity and also space complexity increase
 * during allocation and deallocation of memory blocks so guarded memory
 * allocation should only be activated during Debug mode.
 *
 * For Release targets lockfree allocator should be used instead.
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------- */
/** \name Query Methods
 * \{ */

/** Returns the size of the allocated memory block. */
extern size_t (*MEM_allocN_length)(const void *vptr);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Allocation Methods
 * \{ */

/**
 * \brief Allocates a named memory block.
 *
 * \param[in] size The size, in bytes, of the memory block we want to allocate.
 * \param[in] identity A static string identifying the memory block.
 *
 * \return If the function succeeds, the return value is a pointer to the
 * allocated memory block.
 */
extern void *(*MEM_mallocN)(size_t size, char const *identity);
/**
 * \brief Allocates an alligned named memory block.
 *
 * \param[in] size The size, in bytes, of the memory block we want to allocate.
 * \param[in] align The alignment, in bytes, of the memory block we want to
 * allocate. \param[in] identity A static string identifying the memory block.
 *
 * \return If the function succeeds, the return value is a pointer to the
 * allocated memory block.
 */
extern void *(*MEM_mallocN_aligned)(size_t size, size_t align, char const *identity);

/**
 * \brief Allocates a named memory block. The allocated memory is initialized to
 * zero.
 *
 * \param[in] size The size, in bytes, of the memory block we want to allocate.
 * \param[in] identity A static string identifying the memory block.
 *
 * \return If the function succeeds, the return value is a pointer to the
 * allocated memory block.
 */
extern void *(*MEM_callocN)(size_t size, char const *identity);
/**
 * \brief Allocates an alligned named memory block. The allocated memory is
 * initialized to zero.
 *
 * \param[in] size The size, in bytes, of the memory block we want to allocate.
 * \param[in] align The alignment, in bytes, of the memory block we want to
 * allocate. \param[in] identity A static string identifying the memory block.
 *
 * \return If the function succeeds, the return value is a pointer to the
 * allocated memory block.
 */
extern void *(*MEM_callocN_aligned)(size_t size, size_t align, char const *identity);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Reallocation Methods
 * \{ */

/**
 * \brief Reallocate a memory block.
 *
 * \param[in] vptr Pointer to the previously allocated memory block.
 * \param[in] size The new size, in bytes.
 * \param[in] identity A static string identifying the memory block.
 *
 * \note The identity of the block is not changed if the memory block was
 * already named. \note If the function fails the old pointer remains valid.
 *
 * \return If the function succeeds, the return value is a pointer to the
 * reallocated memory block.
 */
extern void *(*MEM_reallocN_id)(void *vptr, size_t size, char const *identity);
/**
 * \brief Reallocate a memory block. Any extra allocated memory is initialized
 * to zero.
 *
 * \param[in] vptr Pointer to the previously allocated memory block.
 * \param[in] size The new size, in bytes.
 * \param[in] identity A static string identifying the memory block.
 *
 * \note The identity of the block is not changed if the memory block was
 * already named. \note If the function fails the old pointer remains valid.
 *
 * \return If the function succeeds, the return value is a pointer to the
 * reallocated memory block.
 */
extern void *(*MEM_recallocN_id)(void *vptr, size_t size, char const *identity);

#define MEM_reallocN(vptr, size) MEM_reallocN_id(vptr, size, __func__)
#define MEM_recallocN(vptr, size) MEM_recallocN_id(vptr, size, __func__)

/** \} */

/* -------------------------------------------------------------------- */
/** \name Duplication Methods
 * \{ */

/**
 * \brief Duplicates a memory block.
 *
 * \param[in] vptr Pointer to the previously allocated memory block.
 *
 * \note This function returns NULL only if vptr is NULL.
 *
 * \return If the function succeeds, the return value is a pointer to the
 * duplicated memory block.
 */
extern void *(*MEM_dupallocN)(void const *vptr);

/** \} */

/* -------------------------------------------------------------------- */
/** \name Deallocation Methods
 * \{ */

/**
 * \brief Deallocates or frees a memory block.
 *
 * \param[in] vptr Previously allocated memory block to be freed.
 */
extern void (*MEM_freeN)(void *vptr);

#ifdef __cplusplus
#	define MEM_SAFE_FREE(v)                                             \
		do {                                                             \
			static_assert(std::is_pointer_v<std::decay_t<decltype(v)>>); \
			void **_v = (void **)&(v);                                   \
			if (*_v) {                                                   \
				MEM_freeN(*_v);                                          \
				*_v = NULL;                                              \
			}                                                            \
		} while (0)
#else
#	define MEM_SAFE_FREE(v)           \
		do {                           \
			void **_v = (void **)&(v); \
			if (*_v) {                 \
				MEM_freeN(*_v);        \
				*_v = NULL;            \
			}                          \
		} while (0)
#endif

/** \} */

/* -------------------------------------------------------------------- */
/** \name Module Methods
 * \{ */

/**
 * \brief Display all the currently active allocated memory blocks.
 */
extern void (*MEM_print_memlist)();

/**
 * Returns the number of memory blocks currently in use.
 */
size_t MEM_num_memory_blocks_in_use();

/**
 * Returns the total number of allocated bytes.
 */
size_t MEM_num_memory_in_use();

/**
 * This should be called as early as possible in the program.
 * When it has been called, information about memory leaks will be printed on
 * exit.
 */
void MEM_init_memleak_detection();

/**
 * Use this if we want to call #exit during argument parsing for example,
 * without having to free all data.
 */
void MEM_use_memleak_detection(bool enabled);

/**
 * When this has been called and memory leaks have been detected,
 * the process will have an exit code that indicates failure.
 * This can be used for when checking for memory leaks with automated tests.
 */
void MEM_enable_fail_on_memleak(void);

/**
 * \brief Switch allocator to fast mode, with less tracking.
 *
 * Use in the production code where performance is the priority, and exact
 * details about allocation is not. This allocator keeps track of number of
 * allocation and amount of allocated bytes, but it does not track of names of
 * allocated blocks.
 *
 * \note The switch between allocator types can only happen before any
 * allocation did happen.
 */
void MEM_use_lockfree_allocator(void);

/**
 * \brief Switch allocator to slow fully guarded mode.
 *
 * Use for debug purposes. This allocator contains lock section around every
 * allocator call, which makes it slow. What is gained with this is the ability
 * to have list of allocated blocks (in an addition to the tracking of number of
 * allocations and amount of allocated bytes).
 *
 * \note The switch between allocator types can only happen before any
 * allocation did happen.
 */
void MEM_use_guarded_allocator(void);

/** \} */

#ifdef __cplusplus
}
#endif

/** Overhead for lockfree allocator (use to avoid slop-space). */
#define MEM_SIZE_OVERHEAD sizeof(size_t)
#define MEM_SIZE_OPTIMAL(size) ((size) - MEM_SIZE_OVERHEAD)

#ifdef __cplusplus

#	include <new>
#	include <type_traits>
#	include <utility>

/**
 * Conservative value of memory alignment returned by non-aligned OS-level
 * memory allocation functions. For alignments smaller than this value, using
 * non-aligned versions of allocator API functions is okay, allowing use of
 * `calloc`, for example.
 */
#	define MEM_MIN_CPP_ALIGNMENT (__STDCPP_DEFAULT_NEW_ALIGNMENT__ < alignof(void *) ? __STDCPP_DEFAULT_NEW_ALIGNMENT__ : alignof(void *))

/**
 * Allocate new memory for and constructs an object of type #T.
 * #MEM_delete should be used to delete the object. Just calling #MEM_freeN is
 * not enough when #T is not a trivial type.
 *
 * Note that when no arguments are passed, C++ will do recursive member-wise
 * value initialization. That is because C++ differentiates between creating an
 * object with `T` (default initialization) and `T()` (value initialization),
 * whereby this function does the latter. Value initialization rules are
 * complex, but for C-style structs, memory will be zero-initialized. So this
 * doesn't match a `malloc()`, but a `calloc()` call in this case. See
 * https://stackoverflow.com/a/4982720.
 */
template<typename T, typename... Args> inline T *MEM_new(char const *allocation_name, Args &&...args) {
	void *buffer = MEM_mallocN_aligned(sizeof(T), alignof(T), allocation_name);
	return new (buffer) T(std::forward<Args>(args)...);
}

/**
 * Destructs and deallocates an object previously allocated with any `MEM_*`
 * function. Passing in null does nothing.
 */
template<typename T> inline void MEM_delete(T const *ptr) {
	static_assert(!std::is_void_v<T>, "MEM_delete on a void pointer not possible. Cast it to a non-void type?");
	if (ptr == nullptr) {
		/* Support #ptr being null, because C++ `delete` supports that as well. */
		return;
	}
	/* C++ allows destruction of `const` objects, so the pointer is allowed to be
	 * `const`. */
	ptr->~T();
	MEM_freeN(const_cast<T *>(ptr));
}

/**
 * Allocates zero-initialized memory for an object of type #T. The constructor
 * of #T is not called, therefor this should only used with trivial types (like
 * all C types). It's valid to call #MEM_freeN on a pointer returned by this,
 * because a destructor call is not necessary, because the type is trivial.
 */
template<typename T> inline T *MEM_cnew(char const *allocation_name) {
	static_assert(std::is_trivial_v<T>, "For non-trivial types, MEM_new should be used.");
	return static_cast<T *>(MEM_callocN_aligned(sizeof(T), alignof(T), allocation_name));
}

/**
 * Same as MEM_cnew but for arrays, better alternative to #MEM_calloc_arrayN.
 */
template<typename T> inline T *MEM_cnew_array(size_t const length, char const *allocation_name) {
	static_assert(std::is_trivial_v<T>, "For non-trivial types, MEM_new should be used.");
	return static_cast<T *>(MEM_callocN_aligned(sizeof(T[length]), alignof(T), allocation_name));
}

/**
 * Allocate memory for an object of type #T and copy construct an object from
 * `other`. Only applicable for a trivial types.
 *
 * This function works around problem of copy-constructing DNA structs which
 * contains deprecated fields: some compilers will generate access deprecated
 * field in implicitly defined copy constructors.
 *
 * This is a better alternative to #MEM_dupallocN.
 */
template<typename T> inline T *MEM_cnew(char const *allocation_name, T const &other) {
	static_assert(std::is_trivial_v<T>, "For non-trivial types, MEM_new should be used.");
	T *new_object = static_cast<T *>(MEM_mallocN(sizeof(T), allocation_name));
	if (new_object) {
		memcpy(new_object, &other, sizeof(T));
	}
	return new_object;
}

/** Allocation functions (for C++ only). */
#	define MEM_CXX_CLASS_ALLOC_FUNCS(_id)                                                     \
	public:                                                                                    \
		void *operator new(size_t num_bytes) {                                                 \
			return MEM_mallocN_aligned(num_bytes, __STDCPP_DEFAULT_NEW_ALIGNMENT__, _id);      \
		}                                                                                      \
		void *operator new(size_t num_bytes, std::align_val_t alignment) {                     \
			return MEM_mallocN_aligned(num_bytes, size_t(alignment), _id);                     \
		}                                                                                      \
		void operator delete(void *mem) {                                                      \
			if (mem) {                                                                         \
				MEM_freeN(mem);                                                                \
			}                                                                                  \
		}                                                                                      \
		void *operator new[](size_t num_bytes) {                                               \
			return MEM_mallocN_aligned(num_bytes, __STDCPP_DEFAULT_NEW_ALIGNMENT__, _id "[]"); \
		}                                                                                      \
		void *operator new[](size_t num_bytes, std::align_val_t alignment) {                   \
			return MEM_mallocN_aligned(num_bytes, size_t(alignment), _id "[]");                \
		}                                                                                      \
		void operator delete[](void *mem) {                                                    \
			if (mem) {                                                                         \
				MEM_freeN(mem);                                                                \
			}                                                                                  \
		}                                                                                      \
		void *operator new(size_t /*count*/, void *ptr) {                                      \
			return ptr;                                                                        \
		}                                                                                      \
		/**                                                                                    \
		 * This is the matching delete operator to the placement-new operator above.           \
		 * Both parameters will have the same value.                                           \
		 * Without this, we get the warning C4291 on windows.                                  \
		 */                                                                                    \
		void operator delete(void * /*ptr_to_free*/, void * /*ptr*/) {                         \
		}

#endif

#endif	// MEM_GUARDEDALLOC_H
