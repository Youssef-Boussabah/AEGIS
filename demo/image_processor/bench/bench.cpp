// imagelab-bench: reproducible timing of the three ImageLab operations.
//
//   imagelab-bench [--width N] [--height N] [--samples N] [--warmup N]
//                  [--repeat N] [--seed N]
//
// Prints one JSON object (schema "imagelab.bench.v1") on stdout. For each
// operation it times `samples` samples after `warmup` untimed runs; a sample
// is `repeat` back-to-back calls on the same deterministic synthetic image.
// Timing uses std::chrono::steady_clock and excludes image generation.
// The output fingerprint must be identical in every run; it is reported so
// that different builds (variants) can be checked for identical results.
//
// This is a local measurement record, not a shared AEGIS benchmark schema.

#include "imagelab/imagelab.hpp"

#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#ifndef IMAGELAB_VARIANT
#define IMAGELAB_VARIANT "unspecified"
#endif

namespace {

struct Options {
  std::uint32_t width = 1024;
  std::uint32_t height = 768;
  std::uint32_t samples = 9;
  std::uint32_t warmup = 1;
  std::uint32_t repeat = 4;
  std::uint64_t seed = 1;
};

std::optional<std::uint64_t> parse_u64(std::string_view text) {
  if (text.empty() || text.size() > 19)
    return std::nullopt;
  std::uint64_t value = 0;
  for (char c : text) {
    if (c < '0' || c > '9')
      return std::nullopt;
    value = value * 10 + static_cast<std::uint64_t>(c - '0');
  }
  return value;
}

bool parse_options(int argc, char **argv, Options &o) {
  for (int i = 1; i < argc; i += 2) {
    const std::string_view name = argv[i];
    if (i + 1 >= argc) {
      std::fprintf(stderr, "imagelab-bench: %s needs a value\n", argv[i]);
      return false;
    }
    const auto value = parse_u64(argv[i + 1]);
    if (!value) {
      std::fprintf(stderr, "imagelab-bench: %s expects a decimal integer\n",
                   argv[i]);
      return false;
    }
    const auto set32 = [&](std::uint32_t &field, std::uint64_t lo,
                           std::uint64_t hi) {
      if (*value < lo || *value > hi) {
        std::fprintf(stderr,
                     "imagelab-bench: %s must be in [%" PRIu64 ", %" PRIu64
                     "]\n",
                     argv[i], lo, hi);
        return false;
      }
      field = static_cast<std::uint32_t>(*value);
      return true;
    };
    bool ok = false;
    if (name == "--width")
      ok = set32(o.width, 1, imagelab::kMaxDimension);
    else if (name == "--height")
      ok = set32(o.height, 1, imagelab::kMaxDimension);
    else if (name == "--samples")
      ok = set32(o.samples, 1, 1000);
    else if (name == "--warmup")
      ok = set32(o.warmup, 0, 1000);
    else if (name == "--repeat")
      ok = set32(o.repeat, 1, 100000);
    else if (name == "--seed") {
      o.seed = *value;
      ok = true;
    } else {
      std::fprintf(stderr, "imagelab-bench: unknown option %s\n", argv[i]);
    }
    if (!ok)
      return false;
  }
  if (std::uint64_t{o.width} * o.height > imagelab::kMaxPixels) {
    std::fprintf(stderr, "imagelab-bench: image exceeds kMaxPixels\n");
    return false;
  }
  return true;
}

// SplitMix64 (Steele, Lea and Flood): a small, fully specified generator.
struct SplitMix64 {
  std::uint64_t state;
  std::uint64_t next() {
    std::uint64_t z = (state += UINT64_C(0x9E3779B97F4A7C15));
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    return z ^ (z >> 31);
  }
};

// Gradients, hard-edged 32x32 blocks and +-16 noise, so that the enhance
// gate sees both flat and edge regions. Alpha is random.
void fill_synthetic(imagelab::Image &image, std::uint64_t seed) {
  SplitMix64 rng{seed};
  const std::uint32_t w = image.width();
  const std::uint32_t h = image.height();
  for (std::uint32_t y = 0; y < h; ++y) {
    std::uint8_t *row = image.row(y);
    for (std::uint32_t x = 0; x < w; ++x) {
      const std::uint64_t r = rng.next();
      const int block = (((x / 32) + (y / 32)) & 1) ? 48 : -48;
      const int base[3] = {static_cast<int>(w > 1 ? (x * 255u) / (w - 1) : 128),
                           static_cast<int>(h > 1 ? (y * 255u) / (h - 1) : 128),
                           static_cast<int>((x + y) & 0xFFu)};
      for (int c = 0; c < 3; ++c) {
        const int noise = static_cast<int>((r >> (8 * c)) & 31u) - 16;
        row[x * 4 + c] = static_cast<std::uint8_t>(
            std::clamp(base[c] + block + noise, 0, 255));
      }
      row[x * 4 + 3] = static_cast<std::uint8_t>(r >> 32);
    }
  }
}

struct OpResult {
  std::string name;
  std::string params;
  std::uint64_t fingerprint = 0;
  std::vector<std::uint64_t> samples_ns;
};

bool time_op(const Options &o, const imagelab::Image &dst,
             const std::function<imagelab::Status()> &call, OpResult &result) {
  for (std::uint32_t i = 0; i < o.warmup; ++i)
    if (call() != imagelab::Status::ok)
      return false;
  std::optional<std::uint64_t> expected;
  for (std::uint32_t s = 0; s < o.samples; ++s) {
    const auto start = std::chrono::steady_clock::now();
    for (std::uint32_t r = 0; r < o.repeat; ++r)
      if (call() != imagelab::Status::ok)
        return false;
    const auto stop = std::chrono::steady_clock::now();
    result.samples_ns.push_back(static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start)
            .count()));
    const std::uint64_t fp = imagelab::fingerprint(dst.view());
    if (expected && *expected != fp) {
      std::fprintf(stderr,
                   "imagelab-bench: %s output changed between samples\n",
                   result.name.c_str());
      return false;
    }
    expected = fp;
  }
  result.fingerprint = *expected;
  return true;
}

void print_json(const Options &o, const std::vector<OpResult> &results) {
  std::printf("{\n  \"schema\": \"imagelab.bench.v1\",\n");
  std::printf("  \"variant\": \"%s\",\n", IMAGELAB_VARIANT);
#if defined(__VERSION__)
  std::printf("  \"compiler\": \"%s\",\n", __VERSION__);
#endif
  std::printf("  \"width\": %" PRIu32 ",\n  \"height\": %" PRIu32 ",\n",
              o.width, o.height);
  std::printf("  \"samples\": %" PRIu32 ",\n  \"warmup\": %" PRIu32
              ",\n  \"repeat\": %" PRIu32 ",\n",
              o.samples, o.warmup, o.repeat);
  std::printf("  \"seed\": \"%" PRIu64 "\",\n  \"operations\": [\n", o.seed);
  for (std::size_t i = 0; i < results.size(); ++i) {
    const OpResult &r = results[i];
    std::vector<std::uint64_t> sorted = r.samples_ns;
    std::sort(sorted.begin(), sorted.end());
    const std::uint64_t median = sorted[sorted.size() / 2];
    const double pixels = static_cast<double>(o.width) * o.height * o.repeat;
    std::printf("    {\n      \"name\": \"%s\",\n      \"params\": %s,\n",
                r.name.c_str(), r.params.c_str());
    std::printf("      \"fingerprint\": \"%016" PRIx64 "\",\n", r.fingerprint);
    std::printf("      \"samples_ns\": [");
    for (std::size_t s = 0; s < r.samples_ns.size(); ++s)
      std::printf("%s%" PRIu64, s ? ", " : "", r.samples_ns[s]);
    std::printf("],\n");
    std::printf("      \"median_ns\": %" PRIu64 ",\n      \"min_ns\": %" PRIu64
                ",\n      \"max_ns\": %" PRIu64 ",\n",
                median, sorted.front(), sorted.back());
    std::printf("      \"median_ns_per_pixel\": %.4f\n    }%s\n",
                static_cast<double>(median) / pixels,
                i + 1 < results.size() ? "," : "");
  }
  std::printf("  ]\n}\n");
}

} // namespace

int main(int argc, char **argv) {
  Options o;
  if (!parse_options(argc, argv, o))
    return 2;
  imagelab::Image src;
  imagelab::Image dst;
  if (imagelab::Image::create(o.width, o.height, src) != imagelab::Status::ok ||
      imagelab::Image::create(o.width, o.height, dst) != imagelab::Status::ok) {
    std::fprintf(stderr, "imagelab-bench: cannot allocate images\n");
    return 1;
  }
  fill_synthetic(src, o.seed);

  const imagelab::ToneMapParams tone{384, 32768};
  const imagelab::ColorParams color{320, 288, -12};
  const imagelab::EnhanceParams enh{384, 6};
  std::vector<OpResult> results(3);
  results[0].name = "tone";
  results[0].params = "{\"exposure_q8\": 384, \"knee\": 32768}";
  results[1].name = "color";
  results[1].params =
      "{\"saturation_q8\": 320, \"contrast_q8\": 288, \"brightness\": -12}";
  results[2].name = "enhance";
  results[2].params = "{\"amount_q8\": 384, \"threshold\": 6}";

  const bool ok =
      time_op(
          o, dst,
          [&] { return imagelab::tone_map(src.view(), dst.view(), tone); },
          results[0]) &&
      time_op(
          o, dst,
          [&] { return imagelab::adjust_color(src.view(), dst.view(), color); },
          results[1]) &&
      time_op(
          o, dst,
          [&] { return imagelab::enhance(src.view(), dst.view(), enh); },
          results[2]);
  if (!ok) {
    std::fprintf(stderr, "imagelab-bench: operation failed\n");
    return 1;
  }
  print_json(o, results);
  return 0;
}
