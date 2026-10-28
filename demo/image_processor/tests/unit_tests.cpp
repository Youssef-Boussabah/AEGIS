// AEGIS ImageLab unit tests (no external framework).
//
// The kernels are compared against a second implementation written here in
// plain signed 64-bit arithmetic straight from the README formulas, without
// the bias tricks used in src/kernels.cpp. Known-answer values were computed
// separately with exact rational arithmetic (Python fractions) and are noted
// where they appear. Checks run in every build type; they do not use assert().

#include "imagelab/imagelab.hpp"
#include "imagelab/kernels.h"
#include "imagelab/pam.hpp"

#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace {

int g_checks = 0;
int g_failures = 0;

#define CHECK(cond)                                                            \
  do {                                                                         \
    ++g_checks;                                                                \
    if (!(cond)) {                                                             \
      ++g_failures;                                                            \
      std::fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__,    \
                   #cond);                                                     \
    }                                                                          \
  } while (0)

#define CHECK_EQ(a, b)                                                         \
  do {                                                                         \
    ++g_checks;                                                                \
    const auto check_a_ = (a);                                                 \
    const auto check_b_ = (b);                                                 \
    if (!(check_a_ == check_b_)) {                                             \
      ++g_failures;                                                            \
      std::fprintf(                                                            \
          stderr,                                                              \
          "%s:%d: CHECK_EQ failed: %s == %s (%" PRIu64 " vs %" PRIu64 ")\n",   \
          __FILE__, __LINE__, #a, #b, static_cast<std::uint64_t>(check_a_),    \
          static_cast<std::uint64_t>(check_b_));                               \
    }                                                                          \
  } while (0)

// Reports only the first few mismatches of a bulk comparison.
#define CHECK_BULK(cond, ...)                                                  \
  do {                                                                         \
    ++g_checks;                                                                \
    if (!(cond)) {                                                             \
      if (++g_failures <= 20) {                                                \
        std::fprintf(stderr, "%s:%d: CHECK failed: %s: ", __FILE__, __LINE__,  \
                     #cond);                                                   \
        std::fprintf(stderr, __VA_ARGS__);                                     \
        std::fputc('\n', stderr);                                              \
      }                                                                        \
    }                                                                          \
  } while (0)

using imagelab::Status;
using std::int64_t;
using std::uint32_t;
using std::uint64_t;
using std::uint8_t;

struct SplitMix64 {
  uint64_t state;
  uint64_t next() {
    uint64_t z = (state += UINT64_C(0x9E3779B97F4A7C15));
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    return z ^ (z >> 31);
  }
  uint32_t u32() { return static_cast<uint32_t>(next() >> 32); }
  uint32_t below(uint32_t n) { return static_cast<uint32_t>(next() % n); }
};

// ---------------------------------------------------------------------------
// Independent reference model (signed arithmetic, README formulas).

int64_t floor_div(int64_t a, int64_t b) { // b > 0
  int64_t q = a / b;
  if ((a % b) != 0 && a < 0)
    --q;
  return q;
}

int64_t clamp255(int64_t v) { return std::clamp<int64_t>(v, 0, 255); }

uint32_t chan(uint32_t px, int i) { return (px >> (8 * i)) & 0xFF; }
uint32_t pack(int64_t r, int64_t g, int64_t b, uint32_t a) {
  return static_cast<uint32_t>(r) | (static_cast<uint32_t>(g) << 8) |
         (static_cast<uint32_t>(b) << 16) | (a << 24);
}

int64_t ref_tone_channel(int64_t c, int64_t gain, int64_t knee) {
  const int64_t m = 255 * 256;
  const int64_t e = c * gain;
  // y = num / den, rounded half up; computed as quotient + remainder test.
  const int64_t num = 255 * e * (m + knee);
  const int64_t den = m * (e + knee);
  int64_t y = num / den;
  if (2 * (num % den) >= den)
    ++y;
  return std::min<int64_t>(y, 255);
}

uint32_t ref_tone(uint32_t px, int64_t gain, int64_t knee) {
  return pack(ref_tone_channel(chan(px, 0), gain, knee),
              ref_tone_channel(chan(px, 1), gain, knee),
              ref_tone_channel(chan(px, 2), gain, knee), chan(px, 3));
}

uint32_t ref_color(uint32_t px, int64_t sat, int64_t con, int64_t bri) {
  const int64_t r = chan(px, 0), g = chan(px, 1), b = chan(px, 2);
  const int64_t y = (77 * r + 150 * g + 29 * b + 128) / 256;
  const auto one = [&](int64_t c) {
    const int64_t s1 = clamp255(floor_div((c - y) * sat + 256 * y + 128, 256));
    const int64_t s2 =
        clamp255(floor_div((s1 - 128) * con + 256 * 128 + 128, 256));
    return clamp255(s2 + bri);
  };
  return pack(one(r), one(g), one(b), chan(px, 3));
}

int64_t ref_enhance_channel(int64_t c, int64_t n, int64_t s, int64_t w,
                            int64_t e, int64_t amount, int64_t t) {
  const int64_t blur = (4 * c + n + s + w + e + 4) / 8;
  const int64_t hi = std::max({c, n, s, w, e});
  const int64_t lo = std::min({c, n, s, w, e});
  const int64_t range = hi - lo;
  const int64_t gate =
      range <= t ? 0 : std::min<int64_t>(16 * (range - t), 256);
  return clamp255(
      floor_div(65536 * c + (c - blur) * amount * gate + 32768, 65536));
}

uint32_t ref_enhance(uint32_t c, uint32_t n, uint32_t s, uint32_t w, uint32_t e,
                     int64_t amount, int64_t t) {
  int64_t out[3];
  for (int i = 0; i < 3; ++i)
    out[i] = ref_enhance_channel(chan(c, i), chan(n, i), chan(s, i), chan(w, i),
                                 chan(e, i), amount, t);
  return pack(out[0], out[1], out[2], chan(c, 3));
}

uint32_t gray(uint32_t v, uint32_t a = 255) { return pack(v, v, v, a); }

// ---------------------------------------------------------------------------
// Kernel tests

void test_tone_known_answers() {
  // Exact values from Fraction(255*E*(M+K), M*(E+K)), rounded half up.
  CHECK_EQ(imagelab_tone_map_pixel(gray(0), 256, 65280), gray(0));
  CHECK_EQ(imagelab_tone_map_pixel(gray(255), 256, 65280), gray(255));
  CHECK_EQ(chan(imagelab_tone_map_pixel(gray(128), 256, 65280), 0), 170u);
  CHECK_EQ(chan(imagelab_tone_map_pixel(gray(64), 256, 65280), 0), 102u);
  CHECK_EQ(chan(imagelab_tone_map_pixel(gray(200), 512, 16384), 0), 255u);
  CHECK_EQ(chan(imagelab_tone_map_pixel(gray(10), 4096, 1), 0), 255u);
  CHECK_EQ(chan(imagelab_tone_map_pixel(gray(255), 1, 1), 0), 254u);
  CHECK_EQ(chan(imagelab_tone_map_pixel(gray(1), 256, 1u << 20), 0), 1u);
  // Alpha is copied, channels are independent.
  CHECK_EQ(imagelab_tone_map_pixel(pack(0, 255, 0, 77), 256, 65280),
           pack(0, 255, 0, 77));
}

void test_tone_exhaustive_channels() {
  const uint32_t gains[] = {1,   2,   3,    64,   255,  256, 257,
                            384, 512, 1000, 2048, 4095, 4096};
  const uint32_t knees[] = {1,     2,     100,   255,    256,
                            65280, 65535, 65536, 500000, 1u << 20};
  for (uint32_t gain : gains)
    for (uint32_t knee : knees) {
      uint32_t previous = 0;
      for (uint32_t c = 0; c < 256; ++c) {
        const uint32_t px = pack(c, 255 - c, (c * 7) & 255, c ^ 0x5A);
        const uint32_t got = imagelab_tone_map_pixel(px, gain, knee);
        CHECK_BULK(got == ref_tone(px, gain, knee), "c=%u gain=%u knee=%u", c,
                   gain, knee);
        // Monotonic non-decreasing in the input channel.
        CHECK_BULK(chan(got, 0) >= previous, "c=%u gain=%u knee=%u", c, gain,
                   knee);
        previous = chan(got, 0);
      }
    }
  // Monotonic non-decreasing in the exposure gain.
  for (uint32_t c = 0; c < 256; ++c) {
    uint32_t previous = 0;
    for (uint32_t gain = 1; gain <= 4096; gain += 5) {
      const uint32_t y = chan(imagelab_tone_map_pixel(gray(c), gain, 30000), 0);
      CHECK_BULK(y >= previous, "c=%u gain=%u", c, gain);
      previous = y;
    }
  }
}

void test_color_known_answers() {
  // Identity parameters are exact.
  CHECK_EQ(imagelab_color_adjust_pixel(pack(200, 100, 50, 9), 256, 256, 255),
           pack(200, 100, 50, 9));
  // Saturation 0 gives luma: (77*200 + 150*100 + 29*50 + 128) >> 8 = 124.
  CHECK_EQ(imagelab_color_adjust_pixel(pack(200, 100, 50, 9), 0, 256, 255),
           pack(124, 124, 124, 9));
  // Contrast 0 collapses every channel to the pivot 128.
  CHECK_EQ(imagelab_color_adjust_pixel(pack(0, 77, 255, 1), 256, 0, 255),
           pack(128, 128, 128, 1));
  // Brightness saturates at both ends.
  CHECK_EQ(imagelab_color_adjust_pixel(pack(0, 77, 255, 1), 256, 256, 510),
           pack(255, 255, 255, 1));
  CHECK_EQ(imagelab_color_adjust_pixel(pack(0, 77, 255, 1), 256, 256, 0),
           pack(0, 0, 0, 1));
  // Contrast 2.0 around 128: 100 -> 72, 200 -> 255 (saturated), 128 -> 128.
  CHECK_EQ(imagelab_color_adjust_pixel(pack(100, 200, 128, 0), 256, 512, 255),
           pack(72, 255, 128, 0));
}

void test_color_identity_exhaustive() {
  for (uint32_t rgb = 0; rgb < (1u << 24); ++rgb) {
    const uint32_t px = rgb | ((rgb * 2654435761u) & 0xFF000000u);
    CHECK_BULK(imagelab_color_adjust_pixel(px, 256, 256, 255) == px, "px=%08x",
               px);
  }
}

void test_color_random_against_reference() {
  SplitMix64 rng{0xC0105};
  const uint32_t edges[] = {0,   1,   127, 128,  255, 256,
                            257, 511, 512, 1023, 1024};
  for (int i = 0; i < 2000000; ++i) {
    const uint32_t px = rng.u32();
    const uint32_t sat = (i & 3) == 0 ? edges[rng.below(11)] : rng.below(1025);
    const uint32_t con = (i & 5) == 0 ? edges[rng.below(11)] : rng.below(1025);
    const uint32_t bri = rng.below(511);
    CHECK_BULK(imagelab_color_adjust_pixel(px, sat, con, bri) ==
                   ref_color(px, sat, con, static_cast<int64_t>(bri) - 255),
               "px=%08x sat=%u con=%u bri=%u", px, sat, con, bri);
  }
}

void test_enhance_known_answers() {
  // Flat neighbourhood: range 0 <= threshold, unchanged.
  CHECK_EQ(imagelab_enhance_pixel(gray(90, 3), gray(90), gray(90), gray(90),
                                  gray(90), 1024, 0),
           gray(90, 3));
  // Step: c=100, n=s=e=100, w=0 -> blur=(400+300+4)>>3=88, range=100,
  // gate=256; amount 1.0 gives 100 + (100-88) = 112.
  CHECK_EQ(imagelab_enhance_pixel(gray(100, 7), gray(100), gray(100), gray(0),
                                  gray(100), 256, 8),
           gray(112, 7));
  // Same with amount 0 is the identity.
  CHECK_EQ(imagelab_enhance_pixel(gray(100, 7), gray(100), gray(100), gray(0),
                                  gray(100), 0, 8),
           gray(100, 7));
  // Neighbours 90, 110, 100, 100: range 20 > threshold 5, but
  // blur = (400 + 400 + 4) >> 3 = 100, so the detail is 0 and c is unchanged.
  CHECK_EQ(imagelab_enhance_pixel(gray(100), gray(90), gray(110), gray(100),
                                  gray(100), 1024, 5),
           gray(100));
  // Dark pixel next to bright ones saturates to 0: c=10, others 250:
  // blur=(40+1000+4)>>3=130, detail -120, amount 4.0 -> 10-480 -> 0.
  CHECK_EQ(imagelab_enhance_pixel(gray(10), gray(250), gray(250), gray(250),
                                  gray(250), 1024, 0),
           gray(0));
}

void test_enhance_random_against_reference() {
  SplitMix64 rng{0xE4A};
  for (int i = 0; i < 2000000; ++i) {
    uint32_t px[5];
    // Mix fully random pixels with near-flat neighbourhoods so that both gate
    // branches and the ramp are exercised.
    const uint32_t base = rng.u32();
    for (uint32_t &p : px)
      p = (i & 1) ? rng.u32() : (base ^ (rng.u32() & 0x0F0F0F0Fu));
    const uint32_t amount = rng.below(1025);
    const uint32_t t = (i & 2) ? rng.below(256) : rng.below(24);
    CHECK_BULK(
        imagelab_enhance_pixel(px[0], px[1], px[2], px[3], px[4], amount, t) ==
            ref_enhance(px[0], px[1], px[2], px[3], px[4], amount, t),
        "i=%d amount=%u t=%u", i, amount, t);
  }
}

void test_kernels_are_total() {
  // Out-of-range parameters behave exactly like the saturated values.
  SplitMix64 rng{0x7074};
  for (int i = 0; i < 200000; ++i) {
    const uint32_t px = rng.u32(), a = rng.u32(), b = rng.u32(), c = rng.u32();
    const uint32_t gain = std::clamp<uint32_t>(a, 1, 4096);
    const uint32_t knee = std::clamp<uint32_t>(b, 1, 1u << 20);
    CHECK_BULK(imagelab_tone_map_pixel(px, a, b) ==
                   imagelab_tone_map_pixel(px, gain, knee),
               "a=%u b=%u", a, b);
    CHECK_BULK(imagelab_color_adjust_pixel(px, a, b, c) ==
                   imagelab_color_adjust_pixel(px, std::min(a, 1024u),
                                               std::min(b, 1024u),
                                               std::min(c, 510u)),
               "a=%u b=%u c=%u", a, b, c);
    CHECK_BULK(imagelab_enhance_pixel(px, a, b, c, px ^ a, b, c) ==
                   imagelab_enhance_pixel(px, a, b, c, px ^ a,
                                          std::min(b, 1024u),
                                          std::min(c, 255u)),
               "b=%u c=%u", b, c);
  }
  CHECK_EQ(imagelab_tone_map_pixel(gray(128), 0, 0),
           imagelab_tone_map_pixel(gray(128), 1, 1));
  CHECK_EQ(imagelab_tone_map_pixel(gray(128), 0xFFFFFFFFu, 0xFFFFFFFFu),
           imagelab_tone_map_pixel(gray(128), 4096, 1u << 20));
}

// ---------------------------------------------------------------------------
// Image API tests

void fill_random(imagelab::Image &img, uint64_t seed) {
  SplitMix64 rng{seed};
  for (uint32_t y = 0; y < img.height(); ++y)
    for (uint32_t x = 0; x < img.width() * 4; ++x)
      img.row(y)[x] = static_cast<uint8_t>(rng.next());
}

uint32_t pixel_at(const imagelab::Image &img, uint32_t x, uint32_t y) {
  const uint8_t *p = img.row(y) + x * 4;
  return p[0] | (p[1] << 8) | (p[2] << 16) | (uint32_t{p[3]} << 24);
}

bool padding_is(const imagelab::Image &img, uint8_t fill) {
  for (uint32_t y = 0; y < img.height(); ++y)
    for (std::size_t i = img.width() * 4u; i < img.stride(); ++i)
      if (img.row(y)[i] != fill)
        return false;
  return true;
}

bool same_pixels(const imagelab::Image &a, const imagelab::Image &b) {
  if (a.width() != b.width() || a.height() != b.height())
    return false;
  for (uint32_t y = 0; y < a.height(); ++y)
    if (std::memcmp(a.row(y), b.row(y), a.width() * 4u) != 0)
      return false;
  return true;
}

void test_validate_view() {
  uint8_t buffer[64] = {};
  using V = imagelab::ConstImageView;
  CHECK(imagelab::validate_view(V{buffer, 2, 2, 8}) == Status::ok);
  std::size_t span = 0;
  CHECK(imagelab::validate_view(V{buffer, 2, 3, 13}, &span) == Status::ok);
  CHECK_EQ(span, 13u * 2 + 8);
  CHECK(imagelab::validate_view(V{nullptr, 2, 2, 8}) == Status::null_pointer);
  CHECK(imagelab::validate_view(V{buffer, 0, 2, 8}) ==
        Status::invalid_dimensions);
  CHECK(imagelab::validate_view(V{buffer, 2, 0, 8}) ==
        Status::invalid_dimensions);
  CHECK(imagelab::validate_view(V{buffer, imagelab::kMaxDimension + 1, 1,
                                  (imagelab::kMaxDimension + 1) * 4u}) ==
        Status::invalid_dimensions);
  // 32768 x 32768 is within the per-axis limit but over kMaxPixels.
  CHECK(imagelab::validate_view(V{buffer, 32768, 32768, 32768 * 4u}) ==
        Status::invalid_dimensions);
  CHECK(imagelab::validate_view(V{buffer, 8192, 8192, 8192 * 4u}) ==
        Status::ok);
  CHECK(imagelab::validate_view(V{buffer, 2, 2, 7}) == Status::invalid_stride);
  constexpr std::size_t huge = std::numeric_limits<std::size_t>::max();
  CHECK(imagelab::validate_view(V{buffer, 2, 2, huge}) ==
        Status::size_overflow);
  CHECK(imagelab::validate_view(V{buffer, 2, 3, huge / 2}) ==
        Status::size_overflow);
  // A single row ignores the stride beyond the minimum.
  CHECK(imagelab::validate_view(V{buffer, 2, 1, huge / 2}) == Status::ok);
}

void test_parameter_validation() {
  using namespace imagelab;
  CHECK(validate(ToneMapParams{}) == Status::ok);
  CHECK(validate(ToneMapParams{1, 1}) == Status::ok);
  CHECK(validate(ToneMapParams{4096, 1u << 20}) == Status::ok);
  CHECK(validate(ToneMapParams{0, 100}) == Status::invalid_parameter);
  CHECK(validate(ToneMapParams{4097, 100}) == Status::invalid_parameter);
  CHECK(validate(ToneMapParams{256, 0}) == Status::invalid_parameter);
  CHECK(validate(ToneMapParams{256, (1u << 20) + 1}) ==
        Status::invalid_parameter);
  CHECK(validate(ColorParams{}) == Status::ok);
  CHECK(validate(ColorParams{0, 0, -255}) == Status::ok);
  CHECK(validate(ColorParams{1024, 1024, 255}) == Status::ok);
  CHECK(validate(ColorParams{1025, 256, 0}) == Status::invalid_parameter);
  CHECK(validate(ColorParams{256, 1025, 0}) == Status::invalid_parameter);
  CHECK(validate(ColorParams{256, 256, 256}) == Status::invalid_parameter);
  CHECK(validate(ColorParams{256, 256, -256}) == Status::invalid_parameter);
  CHECK(validate(ColorParams{256, 256, std::numeric_limits<int32_t>::min()}) ==
        Status::invalid_parameter);
  CHECK(validate(EnhanceParams{}) == Status::ok);
  CHECK(validate(EnhanceParams{1024, 255}) == Status::ok);
  CHECK(validate(EnhanceParams{1025, 0}) == Status::invalid_parameter);
  CHECK(validate(EnhanceParams{0, 256}) == Status::invalid_parameter);
}

void test_errors_leave_destination_untouched() {
  imagelab::Image src, dst, other;
  CHECK(imagelab::Image::create(5, 4, src) == Status::ok);
  CHECK(imagelab::Image::create(5, 4, dst, 23, 0xEE) == Status::ok);
  CHECK(imagelab::Image::create(4, 5, other) == Status::ok);
  fill_random(src, 1);
  std::memset(dst.view().data, 0xEE, dst.bytes().size());
  const std::vector<uint8_t> before = dst.bytes();
  CHECK(imagelab::tone_map(src.view(), dst.view(), {0, 1}) ==
        Status::invalid_parameter);
  CHECK(imagelab::adjust_color(src.view(), dst.view(), {256, 256, 300}) ==
        Status::invalid_parameter);
  CHECK(imagelab::enhance(src.view(), dst.view(), {2000, 0}) ==
        Status::invalid_parameter);
  CHECK(imagelab::tone_map(other.view(), dst.view(), {}) ==
        Status::dimension_mismatch);
  CHECK(imagelab::enhance(other.view(), dst.view(), {}) ==
        Status::dimension_mismatch);
  imagelab::ImageView null_dst = dst.view();
  null_dst.data = nullptr;
  CHECK(imagelab::adjust_color(src.view(), null_dst, {}) ==
        Status::null_pointer);
  imagelab::ImageView bad_stride = dst.view();
  bad_stride.stride = 19;
  CHECK(imagelab::tone_map(src.view(), bad_stride, {}) ==
        Status::invalid_stride);
  CHECK(dst.bytes() == before);
}

void test_aliasing_rules() {
  imagelab::Image img, reference;
  CHECK(imagelab::Image::create(6, 5, img, 0) == Status::ok);
  fill_random(img, 2);
  const imagelab::Image original = img;
  CHECK(imagelab::Image::create(6, 5, reference) == Status::ok);

  // Exact in-place is allowed for per-pixel operations and matches
  // out-of-place results.
  const imagelab::ToneMapParams tone{700, 9000};
  CHECK(imagelab::tone_map(original.view(), reference.view(), tone) ==
        Status::ok);
  CHECK(imagelab::tone_map(img.view(), img.view(), tone) == Status::ok);
  CHECK(same_pixels(img, reference));
  img = original;
  const imagelab::ColorParams color{600, 300, 20};
  CHECK(imagelab::adjust_color(original.view(), reference.view(), color) ==
        Status::ok);
  CHECK(imagelab::adjust_color(img.view(), img.view(), color) == Status::ok);
  CHECK(same_pixels(img, reference));

  // Enhance never allows overlap.
  img = original;
  CHECK(imagelab::enhance(img.view(), img.view(), {}) == Status::aliasing);
  CHECK(same_pixels(img, original));

  // Partial overlap is rejected for everything. Use a 6x4 window shifted by
  // one pixel inside the 6x5 buffer.
  imagelab::ImageView a = img.view();
  a.height = 4;
  imagelab::ImageView b = a;
  b.data += 4;
  b.width = 5;
  a.width = 5;
  CHECK(imagelab::tone_map(a, b, {}) == Status::aliasing);
  CHECK(imagelab::adjust_color(a, b, {}) == Status::aliasing);
  CHECK(imagelab::enhance(a, b, {}) == Status::aliasing);
  // Same pointer but different stride is not "exact in place".
  imagelab::ImageView c = img.view();
  c.height = 2;
  c.width = 3;
  imagelab::ImageView d = c;
  d.stride = c.stride + 4;
  CHECK(imagelab::tone_map(c, d, {}) == Status::aliasing);
  // Disjoint sub-views of one buffer are fine: rows 0-1 and rows 3-4.
  imagelab::ImageView top = img.view();
  top.height = 2;
  imagelab::ImageView bottom = top;
  bottom.data += 3 * img.stride();
  CHECK(imagelab::enhance(top, bottom, {}) == Status::ok);
}

// Clamp-to-edge driver reference for enhance.
imagelab::Image reference_enhance(const imagelab::Image &src,
                                  const imagelab::EnhanceParams &p) {
  imagelab::Image out;
  imagelab::Image::create(src.width(), src.height(), out);
  const auto at = [&](int64_t x, int64_t y) {
    x = std::clamp<int64_t>(x, 0, src.width() - 1);
    y = std::clamp<int64_t>(y, 0, src.height() - 1);
    return pixel_at(src, static_cast<uint32_t>(x), static_cast<uint32_t>(y));
  };
  for (uint32_t y = 0; y < src.height(); ++y)
    for (uint32_t x = 0; x < src.width(); ++x) {
      const uint32_t v = ref_enhance(at(x, y), at(x, int64_t{y} - 1),
                                     at(x, y + 1), at(int64_t{x} - 1, y),
                                     at(x + 1, y), p.amount_q8, p.threshold);
      for (int i = 0; i < 4; ++i)
        out.row(y)[x * 4 + i] = static_cast<uint8_t>(v >> (8 * i));
    }
  return out;
}

void test_shapes_strides_and_borders() {
  const uint32_t shapes[][2] = {{1, 1}, {1, 7},  {7, 1}, {2, 2},
                                {3, 5}, {17, 9}, {64, 3}};
  const std::size_t extra_padding[] = {0, 1, 3, 13};
  const imagelab::EnhanceParams enh_params[] = {
      {256, 8}, {1024, 0}, {0, 0}, {777, 3}};
  uint64_t seed = 10;
  for (const auto &shape : shapes)
    for (std::size_t pad : extra_padding) {
      const uint32_t w = shape[0], h = shape[1];
      imagelab::Image tight, src, dst;
      CHECK(imagelab::Image::create(w, h, tight) == Status::ok);
      fill_random(tight, ++seed);
      CHECK(imagelab::Image::create(w, h, src, w * 4 + pad, 0xA5) ==
            Status::ok);
      CHECK(imagelab::Image::create(w, h, dst, w * 4 + pad + 2, 0x5A) ==
            Status::ok);
      for (uint32_t y = 0; y < h; ++y)
        std::memcpy(src.row(y), tight.row(y), w * 4u);

      imagelab::Image expected;
      CHECK(imagelab::Image::create(w, h, expected) == Status::ok);
      // Per-pixel operations: padded vs tight give identical pixels.
      CHECK(imagelab::tone_map(tight.view(), expected.view(), {300, 20000}) ==
            Status::ok);
      CHECK(imagelab::tone_map(src.view(), dst.view(), {300, 20000}) ==
            Status::ok);
      CHECK(same_pixels(dst, expected));
      for (uint32_t y = 0; y < h; ++y)
        for (uint32_t x = 0; x < w; ++x)
          CHECK_BULK(pixel_at(dst, x, y) ==
                         ref_tone(pixel_at(src, x, y), 300, 20000),
                     "%ux%u pad=%zu x=%u y=%u", w, h, pad, x, y);
      CHECK(imagelab::adjust_color(src.view(), dst.view(), {0, 512, -3}) ==
            Status::ok);
      for (uint32_t y = 0; y < h; ++y)
        for (uint32_t x = 0; x < w; ++x)
          CHECK_BULK(pixel_at(dst, x, y) ==
                         ref_color(pixel_at(src, x, y), 0, 512, -3),
                     "%ux%u pad=%zu x=%u y=%u", w, h, pad, x, y);
      for (const auto &p : enh_params) {
        CHECK(imagelab::enhance(src.view(), dst.view(), p) == Status::ok);
        CHECK_BULK(same_pixels(dst, reference_enhance(tight, p)),
                   "%ux%u pad=%zu", w, h, pad);
      }
      // Padding is never read into results nor written.
      CHECK(padding_is(src, 0xA5));
      CHECK(padding_is(dst, 0x5A));
    }
}

void test_identity_operations() {
  imagelab::Image src, dst;
  CHECK(imagelab::Image::create(19, 11, src) == Status::ok);
  CHECK(imagelab::Image::create(19, 11, dst) == Status::ok);
  fill_random(src, 77);
  CHECK(imagelab::adjust_color(src.view(), dst.view(), {256, 256, 0}) ==
        Status::ok);
  CHECK(same_pixels(src, dst));
  CHECK(imagelab::enhance(src.view(), dst.view(), {0, 0}) == Status::ok);
  CHECK(same_pixels(src, dst));
  CHECK(imagelab::enhance(src.view(), dst.view(), {1024, 255}) == Status::ok);
  CHECK(same_pixels(src, dst));
}

void test_fingerprint() {
  imagelab::Image a, b;
  CHECK(imagelab::Image::create(1, 1, a) == Status::ok);
  // FNV-1a-64 of four zero bytes (computed independently).
  CHECK_EQ(imagelab::fingerprint(a.view()), UINT64_C(0x4d25767f9dce13f5));
  CHECK(imagelab::Image::create(2, 1, a) == Status::ok);
  for (int i = 0; i < 8; ++i)
    a.row(0)[i] = static_cast<uint8_t>(i + 1);
  CHECK_EQ(imagelab::fingerprint(a.view()), UINT64_C(0x7eb5108b368a78ed));
  // Padding is excluded.
  CHECK(imagelab::Image::create(3, 4, a) == Status::ok);
  CHECK(imagelab::Image::create(3, 4, b, 3 * 4 + 5, 0xFF) == Status::ok);
  fill_random(a, 5);
  for (uint32_t y = 0; y < 4; ++y)
    std::memcpy(b.row(y), a.row(y), 12);
  CHECK_EQ(imagelab::fingerprint(a.view()), imagelab::fingerprint(b.view()));
  CHECK_EQ(imagelab::fingerprint(imagelab::ConstImageView{}), 0u);
}

void test_image_create() {
  imagelab::Image img;
  CHECK(imagelab::Image::create(0, 1, img) == Status::invalid_dimensions);
  CHECK(imagelab::Image::create(1, 0, img) == Status::invalid_dimensions);
  CHECK(imagelab::Image::create(40000, 1, img) == Status::invalid_dimensions);
  CHECK(imagelab::Image::create(4, 4, img, 15) == Status::invalid_stride);
  CHECK(imagelab::Image::create(4, 4, img,
                                std::numeric_limits<std::size_t>::max()) ==
        Status::size_overflow);
  CHECK(imagelab::Image::create(4, 4, img, 20, 0x11) == Status::ok);
  CHECK_EQ(img.stride(), 20u);
  CHECK(padding_is(img, 0x11));
  CHECK_EQ(img.row(3)[15], 0u);
}

// ---------------------------------------------------------------------------
// Codec tests

std::vector<uint8_t> bytes_of(std::string_view s) {
  return std::vector<uint8_t>(s.begin(), s.end());
}

imagelab::pam::Error decode_error(std::string_view text) {
  imagelab::Image img;
  return imagelab::pam::decode(bytes_of(text), img).error;
}

void test_pam_roundtrip_and_inputs() {
  using imagelab::pam::Error;
  imagelab::Image src;
  CHECK(imagelab::Image::create(3, 2, src, 17, 0x99) == Status::ok);
  fill_random(src, 9);
  const auto encoded = imagelab::pam::encode(src.view());
  const std::string header = "P7\nWIDTH 3\nHEIGHT 2\nDEPTH 4\nMAXVAL "
                             "255\nTUPLTYPE RGB_ALPHA\nENDHDR\n";
  CHECK_EQ(encoded.size(), header.size() + 24);
  CHECK(std::equal(header.begin(), header.end(), encoded.begin()));
  imagelab::Image back;
  CHECK(imagelab::pam::decode(encoded, back).error == Error::none);
  CHECK(same_pixels(src, back));

  // P6 with comments; alpha becomes 255.
  std::string p6 = "P6 # comment\n2 # w\n1\n255\n";
  p6 += std::string("\x01\x02\x03\x04\x05\x06", 6);
  imagelab::Image rgb;
  CHECK(imagelab::pam::decode(bytes_of(p6), rgb).error == Error::none);
  CHECK_EQ(pixel_at(rgb, 0, 0), pack(1, 2, 3, 255));
  CHECK_EQ(pixel_at(rgb, 1, 0), pack(4, 5, 6, 255));

  // P7 RGB (depth 3), comments, blank lines, no TUPLTYPE.
  std::string p7 =
      "P7\n# c\n\nWIDTH 1\nHEIGHT 1\nDEPTH 3\nMAXVAL 255\nENDHDR\n";
  p7 += std::string("\x0A\x0B\x0C", 3);
  CHECK(imagelab::pam::decode(bytes_of(p7), rgb).error == Error::none);
  CHECK_EQ(pixel_at(rgb, 0, 0), pack(10, 11, 12, 255));
}

void test_pam_rejects_invalid_input() {
  using imagelab::pam::Error;
  const std::string ok_head =
      "P7\nWIDTH 1\nHEIGHT 1\nDEPTH 4\nMAXVAL 255\nENDHDR\n";
  const std::string px(4, '\x10');
  CHECK(decode_error(ok_head + px) == Error::none);
  CHECK(decode_error("") == Error::format);
  CHECK(decode_error("P5\n1 1\n255\n\x01") == Error::format);
  CHECK(decode_error("P7") == Error::format);
  CHECK(decode_error(ok_head + px.substr(0, 3)) == Error::format); // short
  CHECK(decode_error(ok_head + px + "x") == Error::format);        // trailing
  CHECK(decode_error("P7\nWIDTH 1\nHEIGHT 1\nDEPTH 4\nMAXVAL 255\n") ==
        Error::format);
  CHECK(decode_error("P7\nWIDTH 1\nHEIGHT 1\nDEPTH 4\nMAXVAL 65535\nENDHDR\n" +
                     px) == Error::format);
  CHECK(decode_error(
            "P7\nWIDTH 1\nHEIGHT 1\nDEPTH 1\nMAXVAL 255\nENDHDR\n\x01") ==
        Error::format);
  CHECK(decode_error(
            "P7\nWIDTH 1\nWIDTH 1\nHEIGHT 1\nDEPTH 4\nMAXVAL 255\nENDHDR\n" +
            px) == Error::format);
  CHECK(decode_error(
            "P7\nWIDTH 1\nHEIGHT 1\nDEPTH 4\nMAXVAL 255\nCOLOR 1\nENDHDR\n" +
            px) == Error::format);
  CHECK(
      decode_error(
          "P7\nWIDTH 1\nHEIGHT 1\nDEPTH 4\nMAXVAL 255\nTUPLTYPE RGB\nENDHDR\n" +
          px) == Error::format);
  CHECK(decode_error("P7\nWIDTH +1\nHEIGHT 1\nDEPTH 4\nMAXVAL 255\nENDHDR\n" +
                     px) == Error::format);
  CHECK(decode_error("P7\nWIDTH -1\nHEIGHT 1\nDEPTH 4\nMAXVAL 255\nENDHDR\n" +
                     px) == Error::format);
  CHECK(decode_error(
            "P7\nWIDTH 4294967296\nHEIGHT 1\nDEPTH 4\nMAXVAL 255\nENDHDR\n") ==
        Error::format);
  CHECK(decode_error("P7\nWIDTH 0\nHEIGHT 1\nDEPTH 4\nMAXVAL 255\nENDHDR\n") ==
        Error::format);
  CHECK(decode_error(
            "P7\nWIDTH 40000\nHEIGHT 1\nDEPTH 4\nMAXVAL 255\nENDHDR\n") ==
        Error::limits);
  CHECK(decode_error(
            "P7\nWIDTH 30000\nHEIGHT 30000\nDEPTH 4\nMAXVAL 255\nENDHDR\n") ==
        Error::limits);
  CHECK(decode_error("P7\n" + std::string(5000, '#') + "\nENDHDR\n") ==
        Error::format);
  CHECK(decode_error("P6\n1 1\n65535\n\x01\x02\x03\x04\x05\x06") ==
        Error::format);
  CHECK(decode_error("P6\n1 1\n255") == Error::format);
  CHECK(decode_error("P6\n1 1\n255\n\x01\x02") == Error::format);
  CHECK(decode_error("P6\n1 1 255\n\x01\x02\x03\x04") == Error::format);
  CHECK(decode_error("P61 1 255\n\x01\x02\x03") == Error::format);
}

struct TestCase {
  const char *name;
  void (*fn)();
};

const TestCase kTests[] = {
    {"tone_known_answers", test_tone_known_answers},
    {"tone_exhaustive_channels", test_tone_exhaustive_channels},
    {"color_known_answers", test_color_known_answers},
    {"color_identity_exhaustive", test_color_identity_exhaustive},
    {"color_random_against_reference", test_color_random_against_reference},
    {"enhance_known_answers", test_enhance_known_answers},
    {"enhance_random_against_reference", test_enhance_random_against_reference},
    {"kernels_are_total", test_kernels_are_total},
    {"validate_view", test_validate_view},
    {"parameter_validation", test_parameter_validation},
    {"errors_leave_destination_untouched",
     test_errors_leave_destination_untouched},
    {"aliasing_rules", test_aliasing_rules},
    {"shapes_strides_and_borders", test_shapes_strides_and_borders},
    {"identity_operations", test_identity_operations},
    {"fingerprint", test_fingerprint},
    {"image_create", test_image_create},
    {"pam_roundtrip_and_inputs", test_pam_roundtrip_and_inputs},
    {"pam_rejects_invalid_input", test_pam_rejects_invalid_input},
};

} // namespace

int main(int argc, char **argv) {
  const char *only = argc > 1 ? argv[1] : nullptr;
  int failed_tests = 0;
  int run = 0;
  for (const TestCase &t : kTests) {
    if (only != nullptr && std::strcmp(only, t.name) != 0)
      continue;
    ++run;
    const int before = g_failures;
    t.fn();
    const bool ok = g_failures == before;
    failed_tests += ok ? 0 : 1;
    std::printf("%s %s\n", ok ? "PASS" : "FAIL", t.name);
  }
  if (run == 0) {
    std::fprintf(stderr, "no test named %s\n", only ? only : "");
    return 2;
  }
  std::printf("%d tests, %d failed; %d checks, %d failed\n", run, failed_tests,
              g_checks, g_failures);
  return g_failures == 0 ? 0 : 1;
}
