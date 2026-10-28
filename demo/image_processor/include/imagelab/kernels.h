/*
 * AEGIS ImageLab: protected per-pixel kernels.
 *
 * These are the only functions in ImageLab that carry the "aegis.protect"
 * annotation (see src/kernels.cpp and protect.allowlist). Their signatures use
 * scalar integers only, so the LLVM Shield prototype in protectors/llvm can
 * select them: it accepts only non-variadic functions whose return value and
 * arguments are all scalar integers.
 *
 * Pixel encoding: one RGBA8 pixel packed into a uint32_t as
 *     R | G << 8 | B << 16 | A << 24
 * The image drivers build this value from bytes, so the encoding does not
 * depend on host byte order.
 *
 * Every kernel is total: it has defined, documented output for every possible
 * uint32_t argument. Parameters outside the documented range are saturated to
 * the nearest bound. The public C++ API (imagelab.hpp) rejects out-of-range
 * parameters instead of relying on this saturation.
 *
 * The exact arithmetic is specified in README.md ("Numeric semantics").
 */
#ifndef IMAGELAB_KERNELS_H
#define IMAGELAB_KERNELS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Rational tone curve on R, G and B; alpha is copied.
 * exposure_q8: gain in Q8 (256 = 1.0), saturated to [1, 4096].
 * knee:        curve knee in Q8 channel units, saturated to [1, 1048576]. */
uint32_t imagelab_tone_map_pixel(uint32_t rgba, uint32_t exposure_q8,
                                 uint32_t knee);

/* Saturation, then contrast, then brightness on R, G and B; alpha is copied.
 * saturation_q8, contrast_q8: Q8 factors (256 = 1.0), saturated to [0, 1024].
 * brightness_biased: brightness + 255, saturated to [0, 510]. */
uint32_t imagelab_color_adjust_pixel(uint32_t rgba, uint32_t saturation_q8,
                                     uint32_t contrast_q8,
                                     uint32_t brightness_biased);

/* Range-gated unsharp mask over a 4-neighbourhood; alpha is copied from
 * center.
 * amount_q8: sharpening gain in Q8 (256 = 1.0), saturated to [0, 1024].
 * threshold: local range at or below which nothing is sharpened, saturated
 *            to [0, 255]. */
uint32_t imagelab_enhance_pixel(uint32_t center, uint32_t north, uint32_t south,
                                uint32_t west, uint32_t east,
                                uint32_t amount_q8, uint32_t threshold);

#ifdef __cplusplus
}
#endif

#endif /* IMAGELAB_KERNELS_H */
