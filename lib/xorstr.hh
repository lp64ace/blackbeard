#ifndef XORSTR_HH
#define XORSTR_HH

#if defined(_M_ARM64) || defined(__aarch64__) || defined(_M_ARM) || defined(__arm__)
#	include <arm_neon.h>
#elif defined(_M_X64) || defined(__amd64__) || defined(_M_IX86) || defined(__i386__)
#	include <immintrin.h>
#else
#	error Unsupported platform
#endif

#include "config.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <type_traits>
#include <utility>

#define NEW_XORSTR(buffer) ::webz::xorstring([]() { return buffer; }, std::integral_constant<std::size_t, sizeof(buffer) / sizeof(*buffer)>{}, std::make_index_sequence<::webz::detail::_buffer_size<sizeof(buffer)>()>{})
#define GET_XORSTR(buffer) NEW_XORSTR(buffer).crypt_get()

namespace webz {

namespace detail {

template<std::size_t Size> BOB_INLINE constexpr std::size_t _buffer_size() {
	return ((Size / 16) + (Size % 16 != 0)) * 2;
}

template<std::uint32_t Seed> BOB_INLINE constexpr std::uint32_t key4() noexcept {
	std::uint32_t value = Seed;
	for (char c : __TIME__)
		value = static_cast<std::uint32_t>((value ^ c) * 16777619ull);
	return value;
}

template<std::size_t S> BOB_INLINE constexpr std::uint64_t key8() {
	constexpr auto first_part = key4<2166136261 + S>();
	constexpr auto second_part = key4<first_part>();
	return (static_cast<std::uint64_t>(first_part) << 32) | second_part;
}

// loads up to 8 characters of string into uint64 and xors it with the key
template<std::size_t N, class CharT> BOB_INLINE constexpr std::uint64_t load_xored_str8(std::uint64_t key, std::size_t idx, const CharT *str) noexcept {
	using cast_type = typename std::make_unsigned<CharT>::type;
	constexpr auto value_size = sizeof(CharT);
	constexpr auto idx_offset = 8 / value_size;

	std::uint64_t value = key;
	for (std::size_t i = 0; i < idx_offset && i + idx * idx_offset < N; ++i)
		value ^= (std::uint64_t{static_cast<cast_type>(str[i + idx * idx_offset])} << ((i % idx_offset) * 8 * value_size));

	return value;
}

// forces compiler to use registers instead of stuffing constants in rdata
BOB_INLINE std::uint64_t load_from_reg(std::uint64_t value) noexcept {
#if defined(__clang__) || defined(__GNUC__)
	asm("" : "=r"(value) : "0"(value) :);
	return value;
#else
	volatile std::uint64_t reg = value;
	return reg;
#endif
}

}  // namespace detail

template<class CharT, std::size_t Size, class Keys, class Indices> class xorstring;

template<class CharT, std::size_t Size, std::uint64_t... Keys, std::size_t... Indices> class xorstring<CharT, Size, std::integer_sequence<std::uint64_t, Keys...>, std::index_sequence<Indices...>> {
#ifndef JM_XORSTR_DISABLE_AVX_INTRINSICS
	constexpr static inline std::uint64_t alignment = ((Size > 16) ? 32 : 16);
#else
	constexpr static inline std::uint64_t alignment = 16;
#endif

	alignas(alignment) std::uint64_t _storage[sizeof...(Keys)];

public:
	using value_type = CharT;
	using size_type = std::size_t;
	using pointer = CharT *;
	using const_pointer = const CharT *;

	template<class L> BOB_INLINE xorstring(L l, std::integral_constant<std::size_t, Size>, std::index_sequence<Indices...>) noexcept : _storage{::webz::detail::load_from_reg((std::integral_constant<std::uint64_t, detail::load_xored_str8<Size>(Keys, Indices, l())>::value))...} {
	}

	BOB_INLINE constexpr size_type size() const noexcept {
		return Size - 1;
	}

	BOB_INLINE void crypt() noexcept {
		// everything is inlined by hand because a certain compiler with a certain linker is _very_ slow
#if defined(__clang__)
		alignas(alignment) std::uint64_t arr[]{::webz::detail::load_from_reg(Keys)...};
		std::uint64_t *keys = (std::uint64_t *)::webz::detail::load_from_reg((std::uint64_t)arr);
#else
		alignas(alignment) std::uint64_t keys[]{::webz::detail::load_from_reg(Keys)...};
#endif

#if defined(_M_ARM64) || defined(__aarch64__) || defined(_M_ARM) || defined(__arm__)
#	if defined(__clang__)
		((Indices >= sizeof(_storage) / 16 ? static_cast<void>(0) : __builtin_neon_vst1q_v(reinterpret_cast<uint64_t *>(_storage) + Indices * 2, veorq_u64(__builtin_neon_vld1q_v(reinterpret_cast<const uint64_t *>(_storage) + Indices * 2, 51), __builtin_neon_vld1q_v(reinterpret_cast<const uint64_t *>(keys) + Indices * 2, 51)), 51)), ...);
#	else  // GCC, MSVC
		((Indices >= sizeof(_storage) / 16 ? static_cast<void>(0) : vst1q_u64(reinterpret_cast<uint64_t *>(_storage) + Indices * 2, veorq_u64(vld1q_u64(reinterpret_cast<const uint64_t *>(_storage) + Indices * 2), vld1q_u64(reinterpret_cast<const uint64_t *>(keys) + Indices * 2)))), ...);
#	endif
#elif !defined(JM_XORSTR_DISABLE_AVX_INTRINSICS)
		((Indices >= sizeof(_storage) / 32 ? static_cast<void>(0) : _mm256_store_si256(reinterpret_cast<__m256i *>(_storage) + Indices, _mm256_xor_si256(_mm256_load_si256(reinterpret_cast<const __m256i *>(_storage) + Indices), _mm256_load_si256(reinterpret_cast<const __m256i *>(keys) + Indices)))), ...);

		if constexpr (sizeof(_storage) % 32 != 0)
			_mm_store_si128(reinterpret_cast<__m128i *>(_storage + sizeof...(Keys) - 2), _mm_xor_si128(_mm_load_si128(reinterpret_cast<const __m128i *>(_storage + sizeof...(Keys) - 2)), _mm_load_si128(reinterpret_cast<const __m128i *>(keys + sizeof...(Keys) - 2))));
#else
		((Indices >= sizeof(_storage) / 16 ? static_cast<void>(0) : _mm_store_si128(reinterpret_cast<__m128i *>(_storage) + Indices, _mm_xor_si128(_mm_load_si128(reinterpret_cast<const __m128i *>(_storage) + Indices), _mm_load_si128(reinterpret_cast<const __m128i *>(keys) + Indices)))), ...);
#endif
	}

	BOB_INLINE const_pointer get() const noexcept {
		return reinterpret_cast<const_pointer>(_storage);
	}

	BOB_INLINE pointer get() noexcept {
		return reinterpret_cast<pointer>(_storage);
	}

	BOB_INLINE pointer crypt_get() noexcept {
		// crypt() is inlined by hand because a certain compiler with a certain linker is _very_ slow
#if defined(__clang__)
		alignas(alignment) std::uint64_t arr[]{::webz::detail::load_from_reg(Keys)...};
		std::uint64_t *keys = (std::uint64_t *)::webz::detail::load_from_reg((std::uint64_t)arr);
#else
		alignas(alignment) std::uint64_t keys[]{::webz::detail::load_from_reg(Keys)...};
#endif

#if defined(_M_ARM64) || defined(__aarch64__) || defined(_M_ARM) || defined(__arm__)
#	if defined(__clang__)
		((Indices >= sizeof(_storage) / 16 ? static_cast<void>(0) : __builtin_neon_vst1q_v(reinterpret_cast<uint64_t *>(_storage) + Indices * 2, veorq_u64(__builtin_neon_vld1q_v(reinterpret_cast<const uint64_t *>(_storage) + Indices * 2, 51), __builtin_neon_vld1q_v(reinterpret_cast<const uint64_t *>(keys) + Indices * 2, 51)), 51)), ...);
#	else  // GCC, MSVC
		((Indices >= sizeof(_storage) / 16 ? static_cast<void>(0) : vst1q_u64(reinterpret_cast<uint64_t *>(_storage) + Indices * 2, veorq_u64(vld1q_u64(reinterpret_cast<const uint64_t *>(_storage) + Indices * 2), vld1q_u64(reinterpret_cast<const uint64_t *>(keys) + Indices * 2)))), ...);
#	endif
#elif !defined(JM_XORSTR_DISABLE_AVX_INTRINSICS)
		((Indices >= sizeof(_storage) / 32 ? static_cast<void>(0) : _mm256_store_si256(reinterpret_cast<__m256i *>(_storage) + Indices, _mm256_xor_si256(_mm256_load_si256(reinterpret_cast<const __m256i *>(_storage) + Indices), _mm256_load_si256(reinterpret_cast<const __m256i *>(keys) + Indices)))), ...);

		if constexpr (sizeof(_storage) % 32 != 0)
			_mm_store_si128(reinterpret_cast<__m128i *>(_storage + sizeof...(Keys) - 2), _mm_xor_si128(_mm_load_si128(reinterpret_cast<const __m128i *>(_storage + sizeof...(Keys) - 2)), _mm_load_si128(reinterpret_cast<const __m128i *>(keys + sizeof...(Keys) - 2))));
#else
		((Indices >= sizeof(_storage) / 16 ? static_cast<void>(0) : _mm_store_si128(reinterpret_cast<__m128i *>(_storage) + Indices, _mm_xor_si128(_mm_load_si128(reinterpret_cast<const __m128i *>(_storage) + Indices), _mm_load_si128(reinterpret_cast<const __m128i *>(keys) + Indices)))), ...);
#endif

		return (pointer)(_storage);
	}
};

template<class L, std::size_t Size, std::size_t... Indices> xorstring(L l, std::integral_constant<std::size_t, Size>, std::index_sequence<Indices...>) -> xorstring<std::remove_const_t<std::remove_reference_t<decltype(l()[0])>>, Size, std::integer_sequence<std::uint64_t, detail::key8<Indices>()...>, std::index_sequence<Indices...>>;

}  // namespace webz

#define XORSTR(str) (&GET_XORSTR((str))[0])

#endif