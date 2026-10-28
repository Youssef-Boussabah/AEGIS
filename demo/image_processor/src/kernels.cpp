// AEGIS ImageLab: protected per-pixel kernels.
//
// This translation unit holds exactly the functions listed in
// protect.allowlist, plus internal helpers that are inlined into them. Keep it
// that way: the build compiles this file on its own to LLVM IR so that a
// protector (for example the LLVM Shield) can transform it and the result can
// be linked in place of the native object.
//
// All arithmetic is unsigned. Signed intermediate values are represented with
// an explicit bias, which keeps every operation free of undefined behaviour
// and leaves additions without overflow flags. Each bias and bound is stated
// next to the code; README.md ("Numeric semantics") gives the specification.
//
// These algorithms are standard, deliberately simple reference targets for
// benchmarking. They are not novel and contain no protection of their own.

#include "imagelab/kernels.h"

#include <cstdint>

#if defined(__clang__) && !defined(IMAGELAB_NO_PROTECT_ANNOTATIONS)
// Exact string matched by the LLVM Shield. noinline keeps the function
// boundary through frontend optimisation; the Shield does not require it.
#define IMAGELAB_PROTECT __attribute__((annotate("aegis.protect"), noinline))
#elif defined(__GNUC__)
#define IMAGELAB_PROTECT __attribute__((noinline))
#else
#define IMAGELAB_PROTECT
#endif

// Helpers are always_inline so that their arithmetic lands inside the
// annotated kernels even when the IR is emitted at -O0 (see README.md,
// "Protector workflow"); the Shield only rewrites annotated function bodies.
#if defined(__GNUC__) || defined(__clang__)
#define IMAGELAB_INLINE [[gnu::always_inline]] inline
#else
#define IMAGELAB_INLINE inline
#endif

namespace {

using u32 = std::uint32_t;
using u64 = std::uint64_t;

IMAGELAB_INLINE constexpr u32 channel(u32 px, unsigned index) {
  return (px >> (8u * index)) & 0xFFu;
}

IMAGELAB_INLINE constexpr u32 pack(u32 r, u32 g, u32 b, u32 a) {
  return r | (g << 8) | (b << 16) | (a << 24);
}

IMAGELAB_INLINE constexpr u32 saturate(u32 value, u32 lo, u32 hi) {
  return value < lo ? lo : (value > hi ? hi : value);
}

// Returns clamp(value - bias, 0, 255) for a value that encodes value - bias.
IMAGELAB_INLINE constexpr u32 unbias_to_u8(u32 value, u32 bias) {
  if (value < bias)
    return 0;
  const u32 v = value - bias;
  return v > 255u ? 255u : v;
}

IMAGELAB_INLINE constexpr u32 min_u32(u32 a, u32 b) { return a < b ? a : b; }
IMAGELAB_INLINE constexpr u32 max_u32(u32 a, u32 b) { return a > b ? a : b; }

// ---- Tone map -------------------------------------------------------------
//
// E = c * gain                       (Q8 channel units; c in [0,255])
// y = 255 * E * (M + K) / (M * (E + K)),   M = 255 * 256
// out = min(255, floor(y + 1/2))
//
// Bounds: E <= 255 * 4096 = 1044480, K <= 2^20, so
// 255 * E * (M + K) < 2.96e14 and 2 * that fits in uint64.
constexpr u64 kToneM = 255u * 256u;

IMAGELAB_INLINE constexpr u32 tone_channel(u32 c, u32 gain, u32 knee) {
  const u64 e = u64{c} * gain;
  const u64 num = 255u * e * (kToneM + knee);
  const u64 den = kToneM * (e + knee);
  const u64 y = (2u * num + den) / (2u * den);
  return y > 255u ? 255u : static_cast<u32>(y);
}

// ---- Colour adjust --------------------------------------------------------
//
// Y  = (77 R + 150 G + 29 B + 128) >> 8
// s1 = clamp(floor(((c  - Y)   * sat + 256 * Y   + 128) / 256))
// s2 = clamp(floor(((s1 - 128) * con + 256 * 128 + 128) / 256))
// s3 = clamp(s2 + brightness)
// clamp() is to [0, 255].

// Bias 1020 * 256 >= Y * sat (<= 255 * 1024): numerator stays non-negative.
constexpr u32 kSatBias = 1020u;
IMAGELAB_INLINE constexpr u32 saturation_stage(u32 c, u32 y, u32 sat) {
  const u32 num = c * sat + 256u * y + kSatBias * 256u - y * sat;
  return unbias_to_u8((num + 128u) >> 8, kSatBias);
}

// Bias 512 * 256 >= 128 * con (<= 128 * 1024).
constexpr u32 kConBias = 512u;
IMAGELAB_INLINE constexpr u32 contrast_stage(u32 c, u32 con) {
  const u32 num = c * con + 256u * 128u + kConBias * 256u - 128u * con;
  return unbias_to_u8((num + 128u) >> 8, kConBias);
}

IMAGELAB_INLINE constexpr u32 brightness_stage(u32 c, u32 brightness_biased) {
  return unbias_to_u8(c + brightness_biased, 255u);
}

IMAGELAB_INLINE constexpr u32 color_channel(u32 c, u32 y, u32 sat, u32 con,
                                            u32 bri) {
  return brightness_stage(contrast_stage(saturation_stage(c, y, sat), con),
                          bri);
}

// ---- Edge-aware enhancement -----------------------------------------------
//
// blur   = (4 c + n + s + w + e + 4) >> 3
// range  = max(c,n,s,w,e) - min(c,n,s,w,e)
// gate   = range <= t ? 0 : min(16 * (range - t), 256)
// out    = clamp(floor((65536 c + (c - blur) * amount * gate + 32768) / 65536))
//
// detail_b = c - blur + 256 lies in [1, 511]; with amount <= 1024 and
// gate <= 256 the product stays below 2^27. Bias 1024 * 65536 = 256 * 1024 *
// 256 >= 256 * amount * gate, and the biased numerator stays below 2^28.
constexpr u32 kEnhanceBias = 1024u;
IMAGELAB_INLINE constexpr u32 enhance_channel(u32 c, u32 n, u32 s, u32 w, u32 e,
                                              u32 amount, u32 threshold) {
  const u32 blur = (4u * c + n + s + w + e + 4u) >> 3;
  const u32 hi = max_u32(max_u32(max_u32(c, n), max_u32(s, w)), e);
  const u32 lo = min_u32(min_u32(min_u32(c, n), min_u32(s, w)), e);
  const u32 range = hi - lo;
  const u32 gate =
      range <= threshold ? 0u : min_u32(16u * (range - threshold), 256u);
  const u32 detail_b = c + 256u - blur;
  const u32 num = 65536u * c + detail_b * amount * gate +
                  kEnhanceBias * 65536u - 256u * amount * gate;
  return unbias_to_u8((num + 32768u) >> 16, kEnhanceBias);
}

} // namespace

extern "C" {

IMAGELAB_PROTECT uint32_t imagelab_tone_map_pixel(uint32_t rgba,
                                                  uint32_t exposure_q8,
                                                  uint32_t knee) {
  const u32 gain = saturate(exposure_q8, 1u, 4096u);
  const u32 k = saturate(knee, 1u, 1u << 20);
  return pack(tone_channel(channel(rgba, 0), gain, k),
              tone_channel(channel(rgba, 1), gain, k),
              tone_channel(channel(rgba, 2), gain, k), channel(rgba, 3));
}

IMAGELAB_PROTECT uint32_t
imagelab_color_adjust_pixel(uint32_t rgba, uint32_t saturation_q8,
                            uint32_t contrast_q8, uint32_t brightness_biased) {
  const u32 sat = min_u32(saturation_q8, 1024u);
  const u32 con = min_u32(contrast_q8, 1024u);
  const u32 bri = min_u32(brightness_biased, 510u);
  const u32 r = channel(rgba, 0);
  const u32 g = channel(rgba, 1);
  const u32 b = channel(rgba, 2);
  const u32 y = (77u * r + 150u * g + 29u * b + 128u) >> 8;
  return pack(color_channel(r, y, sat, con, bri),
              color_channel(g, y, sat, con, bri),
              color_channel(b, y, sat, con, bri), channel(rgba, 3));
}

IMAGELAB_PROTECT uint32_t imagelab_enhance_pixel(uint32_t center,
                                                 uint32_t north, uint32_t south,
                                                 uint32_t west, uint32_t east,
                                                 uint32_t amount_q8,
                                                 uint32_t threshold) {
  const u32 amount = min_u32(amount_q8, 1024u);
  const u32 t = min_u32(threshold, 255u);
  u32 out[3];
  for (unsigned i = 0; i < 3; ++i)
    out[i] = enhance_channel(channel(center, i), channel(north, i),
                             channel(south, i), channel(west, i),
                             channel(east, i), amount, t);
  return pack(out[0], out[1], out[2], channel(center, 3));
}

} // extern "C"
