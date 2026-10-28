// AEGIS ImageLab: validation and image drivers.
//
// This file is never handed to a protector. It validates arguments, walks the
// image and calls the per-pixel kernels in kernels.cpp through their C ABI.

#include "imagelab/imagelab.hpp"
#include "imagelab/kernels.h"

#include <cstdint>
#include <limits>
#include <new>
#include <stdexcept>
#include <utility>

namespace imagelab {
namespace {

using u32 = std::uint32_t;

u32 load_pixel(const std::uint8_t *p) noexcept {
  return u32{p[0]} | (u32{p[1]} << 8) | (u32{p[2]} << 16) | (u32{p[3]} << 24);
}

void store_pixel(std::uint8_t *p, u32 v) noexcept {
  p[0] = static_cast<std::uint8_t>(v);
  p[1] = static_cast<std::uint8_t>(v >> 8);
  p[2] = static_cast<std::uint8_t>(v >> 16);
  p[3] = static_cast<std::uint8_t>(v >> 24);
}

// Computes stride * (height - 1) + width * 4 without overflow, and keeps the
// result within PTRDIFF_MAX so that pointer arithmetic on it is defined.
Status span_of(u32 width, u32 height, std::size_t stride,
               std::size_t &span) noexcept {
  constexpr std::size_t limit =
      static_cast<std::size_t>(std::numeric_limits<std::ptrdiff_t>::max());
  const std::size_t row_bytes = std::size_t{width} * kChannels;
  const std::size_t rows = height - 1u;
  if (rows != 0 && stride > (limit - row_bytes) / rows)
    return Status::size_overflow;
  span = stride * rows + row_bytes;
  return Status::ok;
}

std::uintptr_t address(const void *p) noexcept {
  return reinterpret_cast<std::uintptr_t>(p);
}

// Byte ranges [a, a + a_len) and [b, b + b_len) intersect.
bool overlaps(const void *a, std::size_t a_len, const void *b,
              std::size_t b_len) noexcept {
  const std::uintptr_t a0 = address(a);
  const std::uintptr_t b0 = address(b);
  return a0 < b0 + b_len && b0 < a0 + a_len;
}

enum class AliasPolicy { allow_exact_in_place, forbid_any_overlap };

Status validate_pair(const ConstImageView &src, const ImageView &dst,
                     AliasPolicy policy) noexcept {
  std::size_t src_span = 0;
  std::size_t dst_span = 0;
  if (Status s = validate_view(src, &src_span); s != Status::ok)
    return s;
  if (Status s = validate_view(dst, &dst_span); s != Status::ok)
    return s;
  if (src.width != dst.width || src.height != dst.height)
    return Status::dimension_mismatch;
  if (!overlaps(src.data, src_span, dst.data, dst_span))
    return Status::ok;
  if (policy == AliasPolicy::allow_exact_in_place && src.data == dst.data &&
      src.stride == dst.stride)
    return Status::ok;
  return Status::aliasing;
}

template <typename PixelFn>
void for_each_pixel(const ConstImageView &src, const ImageView &dst,
                    PixelFn fn) noexcept {
  for (u32 y = 0; y < src.height; ++y) {
    const std::uint8_t *in = src.data + std::size_t{y} * src.stride;
    std::uint8_t *out = dst.data + std::size_t{y} * dst.stride;
    for (u32 x = 0; x < src.width; ++x)
      store_pixel(out + std::size_t{x} * kChannels,
                  fn(load_pixel(in + std::size_t{x} * kChannels)));
  }
}

} // namespace

const char *status_name(Status status) noexcept {
  switch (status) {
  case Status::ok:
    return "ok";
  case Status::null_pointer:
    return "null_pointer";
  case Status::invalid_dimensions:
    return "invalid_dimensions";
  case Status::invalid_stride:
    return "invalid_stride";
  case Status::size_overflow:
    return "size_overflow";
  case Status::dimension_mismatch:
    return "dimension_mismatch";
  case Status::aliasing:
    return "aliasing";
  case Status::invalid_parameter:
    return "invalid_parameter";
  case Status::out_of_memory:
    return "out_of_memory";
  }
  return "unknown";
}

Status validate_view(const ConstImageView &view,
                     std::size_t *span_bytes) noexcept {
  if (view.data == nullptr)
    return Status::null_pointer;
  if (view.width == 0 || view.height == 0 || view.width > kMaxDimension ||
      view.height > kMaxDimension ||
      std::uint64_t{view.width} * view.height > kMaxPixels)
    return Status::invalid_dimensions;
  if (view.stride < std::size_t{view.width} * kChannels)
    return Status::invalid_stride;
  std::size_t span = 0;
  if (Status s = span_of(view.width, view.height, view.stride, span);
      s != Status::ok)
    return s;
  // The span must also fit in the address space after view.data.
  if (address(view.data) > std::numeric_limits<std::uintptr_t>::max() - span)
    return Status::size_overflow;
  if (span_bytes != nullptr)
    *span_bytes = span;
  return Status::ok;
}

Status validate(const ToneMapParams &p) noexcept {
  if (p.exposure_q8 < 1 || p.exposure_q8 > 4096 || p.knee < 1 ||
      p.knee > (1u << 20))
    return Status::invalid_parameter;
  return Status::ok;
}

Status validate(const ColorParams &p) noexcept {
  if (p.saturation_q8 > 1024 || p.contrast_q8 > 1024 || p.brightness < -255 ||
      p.brightness > 255)
    return Status::invalid_parameter;
  return Status::ok;
}

Status validate(const EnhanceParams &p) noexcept {
  if (p.amount_q8 > 1024 || p.threshold > 255)
    return Status::invalid_parameter;
  return Status::ok;
}

Status tone_map(const ConstImageView &src, const ImageView &dst,
                const ToneMapParams &params) noexcept {
  if (Status s = validate(params); s != Status::ok)
    return s;
  if (Status s = validate_pair(src, dst, AliasPolicy::allow_exact_in_place);
      s != Status::ok)
    return s;
  const u32 gain = params.exposure_q8;
  const u32 knee = params.knee;
  for_each_pixel(src, dst, [gain, knee](u32 px) {
    return imagelab_tone_map_pixel(px, gain, knee);
  });
  return Status::ok;
}

Status adjust_color(const ConstImageView &src, const ImageView &dst,
                    const ColorParams &params) noexcept {
  if (Status s = validate(params); s != Status::ok)
    return s;
  if (Status s = validate_pair(src, dst, AliasPolicy::allow_exact_in_place);
      s != Status::ok)
    return s;
  const u32 sat = params.saturation_q8;
  const u32 con = params.contrast_q8;
  // validate() guarantees brightness + 255 lies in [0, 510].
  const u32 bri = static_cast<u32>(params.brightness + 255);
  for_each_pixel(src, dst, [sat, con, bri](u32 px) {
    return imagelab_color_adjust_pixel(px, sat, con, bri);
  });
  return Status::ok;
}

Status enhance(const ConstImageView &src, const ImageView &dst,
               const EnhanceParams &params) noexcept {
  if (Status s = validate(params); s != Status::ok)
    return s;
  if (Status s = validate_pair(src, dst, AliasPolicy::forbid_any_overlap);
      s != Status::ok)
    return s;
  const u32 w = src.width;
  const u32 h = src.height;
  const auto at = [&src](u32 x, u32 y) {
    return load_pixel(src.data + std::size_t{y} * src.stride +
                      std::size_t{x} * kChannels);
  };
  for (u32 y = 0; y < h; ++y) {
    const u32 yn = y == 0 ? 0 : y - 1;
    const u32 ys = y + 1 == h ? y : y + 1;
    std::uint8_t *out = dst.data + std::size_t{y} * dst.stride;
    for (u32 x = 0; x < w; ++x) {
      const u32 xw = x == 0 ? 0 : x - 1;
      const u32 xe = x + 1 == w ? x : x + 1;
      store_pixel(out + std::size_t{x} * kChannels,
                  imagelab_enhance_pixel(at(x, y), at(x, yn), at(x, ys),
                                         at(xw, y), at(xe, y), params.amount_q8,
                                         params.threshold));
    }
  }
  return Status::ok;
}

std::uint64_t fingerprint(const ConstImageView &view) noexcept {
  if (validate_view(view) != Status::ok)
    return 0;
  std::uint64_t hash = UINT64_C(14695981039346656037);
  const std::size_t row_bytes = std::size_t{view.width} * kChannels;
  for (u32 y = 0; y < view.height; ++y) {
    const std::uint8_t *row = view.data + std::size_t{y} * view.stride;
    for (std::size_t i = 0; i < row_bytes; ++i) {
      hash ^= row[i];
      hash *= UINT64_C(1099511628211);
    }
  }
  return hash;
}

Status Image::create(u32 width, u32 height, Image &out, std::size_t stride,
                     std::uint8_t padding_fill) noexcept {
  if (width == 0 || height == 0 || width > kMaxDimension ||
      height > kMaxDimension || std::uint64_t{width} * height > kMaxPixels)
    return Status::invalid_dimensions;
  const std::size_t row_bytes = std::size_t{width} * kChannels;
  if (stride == 0)
    stride = row_bytes;
  if (stride < row_bytes)
    return Status::invalid_stride;
  std::size_t span = 0;
  if (Status s = span_of(width, height, stride, span); s != Status::ok)
    return s;
  Image image;
  try {
    // Allocate whole rows so that row(y) + stride is valid for every row.
    if (height > 0 && stride > std::numeric_limits<std::size_t>::max() / height)
      return Status::size_overflow;
    image.pixels_.assign(stride * height, padding_fill);
  } catch (const std::bad_alloc &) {
    return Status::out_of_memory;
  } catch (const std::length_error &) {
    return Status::size_overflow;
  }
  // Visible pixels start as zero; only padding keeps padding_fill.
  for (u32 y = 0; y < height; ++y)
    for (std::size_t i = 0; i < row_bytes; ++i)
      image.pixels_[y * stride + i] = 0;
  image.width_ = width;
  image.height_ = height;
  image.stride_ = stride;
  out = std::move(image);
  return Status::ok;
}

} // namespace imagelab
