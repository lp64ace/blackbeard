#ifndef SPOOF_H
#define SPOOF_H

#include "variadic.h"

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

void *spoof(const void *trampoline, void *function, int nparam, ...);

/* -------------------------------------------------------------------- */
/** \name SPOOF Macro
 * \{ */

/* clang-format off */

#define _VA_SPOOF_2(a0, b0) spoof(a0, b0, 0x0)
#define _VA_SPOOF_3(a0, b0, c0) spoof(a0, b0, 0x1, (void *)(c0))
#define _VA_SPOOF_4(a0, b0, c0, d0) spoof(a0, b0, 0x2, (void *)(c0), (void *)(d0))
#define _VA_SPOOF_5(a0, b0, c0, d0, e0) spoof(a0, b0, 0x3, (void *)(c0), (void *)(d0), (void *)(e0))
#define _VA_SPOOF_6(a0, b0, c0, d0, e0, f0) spoof(a0, b0, 0x4, (void *)(c0), (void *)(d0), (void *)(e0), (void *)(f0))
#define _VA_SPOOF_7(a0, b0, c0, d0, e0, f0, g0) spoof(a0, b0, 0x5, (void *)(c0), (void *)(d0), (void *)(e0), (void *)(f0), (void *)(g0))
#define _VA_SPOOF_8(a0, b0, c0, d0, e0, f0, g0, h0) spoof(a0, b0, 0x6, (void *)(c0), (void *)(d0), (void *)(e0), (void *)(f0), (void *)(g0), (void *)(h0))
#define _VA_SPOOF_9(a0, b0, c0, d0, e0, f0, g0, h0, i0) spoof(a0, b0, 0x7, (void *)(c0), (void *)d0, (void *)(e0), (void *)(f0), (void *)(g0), (void *)(h0), (void *)(i0))
#define _VA_SPOOF_10(a0, b0, c0, d0, e0, f0, g0, h0, i0, j0) spoof(a0, b0, 0x8, (void *)(c0), (void *)d0, (void *)(e0), (void *)(f0), (void *)(g0), (void *)(h0), (void *)(i0), (void *)(j0))
#define _VA_SPOOF_11(a0, b0, c0, d0, e0, f0, g0, h0, i0, j0, k0) spoof(a0, b0, 0x9, (void *)(c0), (void *)d0, (void *)(e0), (void *)(f0), (void *)(g0), (void *)(h0), (void *)(i0), (void *)(j0), (void *)(k0))
#define _VA_SPOOF_12(a0, b0, c0, d0, e0, f0, g0, h0, i0, j0, k0, l0) spoof(a0, b0, 0xa, (void *)(c0), (void *)d0, (void *)(e0), (void *)(f0), (void *)(g0), (void *)(h0), (void *)(i0), (void *)(j0), (void *)(k0), (void *)(l0))
#define _VA_SPOOF_13(a0, b0, c0, d0, e0, f0, g0, h0, i0, j0, k0, l0, m0) spoof(a0, b0, 0xb, (void *)(c0), (void *)d0, (void *)(e0), (void *)(f0), (void *)(g0), (void *)(h0), (void *)(i0), (void *)(j0), (void *)(k0), (void *)(l0), (void *)(m0))
#define _VA_SPOOF_14(a0, b0, c0, d0, e0, f0, g0, h0, i0, j0, k0, l0, m0, n0) spoof(a0, b0, 0xc, (void *)(c0), (void *)d0, (void *)(e0), (void *)(f0), (void *)(g0), (void *)(h0), (void *)(i0), (void *)(j0), (void *)(k0), (void *)(l0), (void *)(m0), (void *)(n0))
#define _VA_SPOOF_15(a0, b0, c0, d0, e0, f0, g0, h0, i0, j0, k0, l0, m0, n0, o0) spoof(a0, b0, 0xd, (void *)(c0), (void *)d0, (void *)(e0), (void *)(f0), (void *)(g0), (void *)(h0), (void *)(i0), (void *)(j0), (void *)(k0), (void *)(l0), (void *)(m0), (void *)(n0), (void *)(o0))
#define _VA_SPOOF_16(a0, b0, c0, d0, e0, f0, g0, h0, i0, j0, k0, l0, m0, n0, o0, p0) spoof(a0, b0, 0xe, (void *)(c0), (void *)d0, (void *)(e0), (void *)(f0), (void *)(g0), (void *)(h0), (void *)(i0), (void *)(j0), (void *)(k0), (void *)(l0), (void *)(m0), (void *)(n0), (void *)(o0), (void *)(p0))

/* clang-format on */

/** Reusable SPOOF macro */
#define SPOOF(...) BOB_VA_NARGS_CALL_OVERLOAD(_VA_SPOOF_, __VA_ARGS__)

/** \} */

#ifdef __cplusplus
}
#endif

#endif
