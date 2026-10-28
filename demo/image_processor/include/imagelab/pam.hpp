// AEGIS ImageLab: strict Netpbm codec for the CLI and tests.
//
// Reads:  PAM "P7" with DEPTH 4 (TUPLTYPE RGB_ALPHA) or DEPTH 3 (TUPLTYPE
//         RGB), and binary PPM "P6"; MAXVAL must be 255. Three-channel input
//         gets alpha 255.
// Writes: PAM "P7", DEPTH 4, TUPLTYPE RGB_ALPHA, MAXVAL 255.
//
// Anything else is rejected rather than guessed: other magic numbers or
// depths, 16-bit samples, unknown or duplicate header keys, a header longer
// than kMaxHeaderBytes, short payloads, and trailing bytes after the single
// image. Dimension limits are those of imagelab.hpp.
#ifndef IMAGELAB_PAM_HPP
#define IMAGELAB_PAM_HPP

#include "imagelab/imagelab.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace imagelab::pam {

inline constexpr std::size_t kMaxHeaderBytes = 4096;

enum class Error {
  none = 0,
  io,     // file could not be opened, read, written or renamed
  format, // bytes are not an accepted Netpbm image
  limits, // well-formed header, but dimensions exceed ImageLab limits
};

struct Result {
  Error error = Error::none;
  std::string message;
  explicit operator bool() const noexcept { return error == Error::none; }
};

Result decode(std::span<const std::uint8_t> bytes, Image &out);
Result read_file(const std::string &path, Image &out);

// Returns an empty vector if the view is invalid.
std::vector<std::uint8_t> encode(const ConstImageView &view);

// Writes to a temporary file in the destination directory, then renames it
// over `path`, so readers never observe a partial image.
Result write_file(const std::string &path, const ConstImageView &view);

} // namespace imagelab::pam

#endif // IMAGELAB_PAM_HPP
