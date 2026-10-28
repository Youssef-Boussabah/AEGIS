// AEGIS ImageLab public C++20 API.
//
// Images are 8-bit RGBA, straight (non-premultiplied) alpha, row-major, four
// interleaved bytes per pixel in R, G, B, A order. Rows may be padded:
// `stride` is the byte distance between the starts of consecutive rows. No
// alignment is required. Operations change R, G and B, copy A, and never
// touch row padding.
//
// Every operation validates its arguments first and returns a Status. On any
// non-ok status nothing has been written to the destination.
#ifndef IMAGELAB_IMAGELAB_HPP
#define IMAGELAB_IMAGELAB_HPP

#include <cstddef>
#include <cstdint>
#include <vector>

namespace imagelab {

inline constexpr std::uint32_t kChannels = 4;
inline constexpr std::uint32_t kMaxDimension = 32768;               // per axis
inline constexpr std::uint64_t kMaxPixels = std::uint64_t{1} << 26; // 64 Mi

enum class Status : int {
  ok = 0,
  null_pointer,       // data pointer (or params) is null
  invalid_dimensions, // width or height is 0, > kMaxDimension, or too many
                      // pixels
  invalid_stride,     // stride < width * 4
  size_overflow,      // stride * (height - 1) + width * 4 does not fit
  dimension_mismatch, // source and destination sizes differ
  aliasing,           // source and destination overlap in an unsupported way
  invalid_parameter,  // a parameter is outside its documented range
  out_of_memory,      // allocation failed (Image::create only)
};

const char *status_name(Status status) noexcept;

struct ConstImageView {
  const std::uint8_t *data = nullptr;
  std::uint32_t width = 0;
  std::uint32_t height = 0;
  std::size_t stride = 0; // bytes between row starts
};

struct ImageView {
  std::uint8_t *data = nullptr;
  std::uint32_t width = 0;
  std::uint32_t height = 0;
  std::size_t stride = 0;

  operator ConstImageView() const noexcept {
    return {data, width, height, stride};
  }
};

// Checks the view and stores the number of bytes it spans,
// stride * (height - 1) + width * 4, in *span_bytes (which may be null).
// The last row needs no padding.
Status validate_view(const ConstImageView &view,
                     std::size_t *span_bytes = nullptr) noexcept;

// Tone mapping with a rational (Reinhard-style) curve after an exposure gain.
struct ToneMapParams {
  std::uint32_t exposure_q8 = 256; // [1, 4096]; 256 = 1.0
  std::uint32_t knee = 65280;      // [1, 1048576]; Q8 channel units
};

// Saturation, contrast and brightness, applied in that order.
struct ColorParams {
  std::uint32_t saturation_q8 = 256; // [0, 1024]; 0 = grey, 256 = unchanged
  std::uint32_t contrast_q8 = 256;   // [0, 1024]; pivot is 128
  std::int32_t brightness = 0;       // [-255, 255]
};

// Range-gated unsharp mask: sharpens only where the local range of the
// 4-neighbourhood exceeds `threshold`.
struct EnhanceParams {
  std::uint32_t amount_q8 = 256; // [0, 1024]; 0 = unchanged
  std::uint32_t threshold = 8;   // [0, 255]
};

Status validate(const ToneMapParams &params) noexcept;
Status validate(const ColorParams &params) noexcept;
Status validate(const EnhanceParams &params) noexcept;

// Per-pixel operations. src and dst must have the same width and height. They
// may be the same image (same data pointer and stride: in-place) or must not
// overlap at all.
Status tone_map(const ConstImageView &src, const ImageView &dst,
                const ToneMapParams &params) noexcept;
Status adjust_color(const ConstImageView &src, const ImageView &dst,
                    const ColorParams &params) noexcept;

// Neighbourhood operation: src and dst must not overlap. Pixels outside the
// image are taken from the nearest edge pixel (clamp-to-edge).
Status enhance(const ConstImageView &src, const ImageView &dst,
               const EnhanceParams &params) noexcept;

// FNV-1a 64-bit hash over the visible bytes of each row (padding excluded),
// row by row. A fast, deterministic fingerprint; not a cryptographic hash.
// Returns 0 for an invalid view (an unusual but possible hash value: check
// validate_view first if that matters).
std::uint64_t fingerprint(const ConstImageView &view) noexcept;

// Owning RGBA8 image with an explicit stride. Padding bytes are filled with
// `padding_fill` so tests can detect stray writes.
class Image {
public:
  Image() = default;

  // stride == 0 means tightly packed (width * 4).
  static Status create(std::uint32_t width, std::uint32_t height, Image &out,
                       std::size_t stride = 0,
                       std::uint8_t padding_fill = 0) noexcept;

  ImageView view() noexcept {
    return {pixels_.data(), width_, height_, stride_};
  }
  ConstImageView view() const noexcept {
    return {pixels_.data(), width_, height_, stride_};
  }
  std::uint32_t width() const noexcept { return width_; }
  std::uint32_t height() const noexcept { return height_; }
  std::size_t stride() const noexcept { return stride_; }
  std::uint8_t *row(std::uint32_t y) noexcept {
    return pixels_.data() + y * stride_;
  }
  const std::uint8_t *row(std::uint32_t y) const noexcept {
    return pixels_.data() + y * stride_;
  }
  const std::vector<std::uint8_t> &bytes() const noexcept { return pixels_; }

private:
  std::vector<std::uint8_t> pixels_;
  std::uint32_t width_ = 0;
  std::uint32_t height_ = 0;
  std::size_t stride_ = 0;
};

} // namespace imagelab

#endif // IMAGELAB_IMAGELAB_HPP
