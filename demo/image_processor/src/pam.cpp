// AEGIS ImageLab: strict Netpbm codec. See pam.hpp for what is accepted.

#include "imagelab/pam.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <limits>
#include <optional>
#include <string_view>
#include <utility>

#if defined(__unix__) || defined(__APPLE__)
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>
#define IMAGELAB_HAVE_MKSTEMP 1
#endif

namespace imagelab::pam {
namespace {

Result fail(Error error, std::string message) {
  return {error, std::move(message)};
}

bool is_space(std::uint8_t c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' ||
         c == '\r';
}

// Decimal digits only; no sign, no leading '+', at most 10 digits, and the
// value must fit in uint32.
std::optional<std::uint32_t> parse_u32(std::string_view text) {
  if (text.empty() || text.size() > 10)
    return std::nullopt;
  std::uint64_t value = 0;
  for (char c : text) {
    if (c < '0' || c > '9')
      return std::nullopt;
    value = value * 10u + static_cast<std::uint64_t>(c - '0');
  }
  if (value > std::numeric_limits<std::uint32_t>::max())
    return std::nullopt;
  return static_cast<std::uint32_t>(value);
}

struct Header {
  std::uint32_t width = 0;
  std::uint32_t height = 0;
  std::uint32_t depth = 0;
  std::size_t payload_offset = 0;
};

Result check_dimensions(const Header &h) {
  if (h.width == 0 || h.height == 0)
    return fail(Error::format, "width and height must be at least 1");
  if (h.width > kMaxDimension || h.height > kMaxDimension ||
      std::uint64_t{h.width} * h.height > kMaxPixels)
    return fail(Error::limits, "image dimensions exceed ImageLab limits");
  return {};
}

// "P7\n" then lines of "KEY value", '#' comments and blank lines, ending
// with a line that is exactly "ENDHDR".
Result parse_p7(std::span<const std::uint8_t> bytes, Header &h) {
  std::size_t pos = 3; // after "P7\n"
  std::optional<std::uint32_t> width, height, depth, maxval;
  std::optional<std::string> tupltype;
  while (true) {
    if (pos >= bytes.size() || pos > kMaxHeaderBytes)
      return fail(Error::format, "PAM header has no ENDHDR line");
    std::size_t end = pos;
    while (end < bytes.size() && bytes[end] != '\n')
      ++end;
    if (end >= bytes.size() || end > kMaxHeaderBytes)
      return fail(Error::format, "PAM header has no ENDHDR line");
    std::string_view line(reinterpret_cast<const char *>(bytes.data()) + pos,
                          end - pos);
    pos = end + 1;
    // Trim spaces, tabs and CR at both ends.
    while (!line.empty() && (line.front() == ' ' || line.front() == '\t'))
      line.remove_prefix(1);
    while (!line.empty() &&
           (line.back() == ' ' || line.back() == '\t' || line.back() == '\r'))
      line.remove_suffix(1);
    if (line.empty() || line.front() == '#')
      continue;
    const std::size_t split = line.find_first_of(" \t");
    const std::string_view key = line.substr(0, split);
    std::string_view value = split == std::string_view::npos
                                 ? std::string_view{}
                                 : line.substr(split);
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
      value.remove_prefix(1);
    if (key == "ENDHDR") {
      if (!value.empty())
        return fail(Error::format, "ENDHDR takes no value");
      break;
    }
    std::optional<std::uint32_t> *slot = nullptr;
    if (key == "WIDTH")
      slot = &width;
    else if (key == "HEIGHT")
      slot = &height;
    else if (key == "DEPTH")
      slot = &depth;
    else if (key == "MAXVAL")
      slot = &maxval;
    if (slot != nullptr) {
      if (slot->has_value())
        return fail(Error::format,
                    "duplicate PAM header key " + std::string(key));
      *slot = parse_u32(value);
      if (!slot->has_value())
        return fail(Error::format, "invalid number for " + std::string(key));
    } else if (key == "TUPLTYPE") {
      if (tupltype.has_value())
        return fail(Error::format, "duplicate PAM header key TUPLTYPE");
      tupltype = std::string(value);
    } else {
      return fail(Error::format, "unknown PAM header key");
    }
  }
  if (!width || !height || !depth || !maxval)
    return fail(Error::format, "PAM header needs WIDTH, HEIGHT, DEPTH, MAXVAL");
  if (*maxval != 255)
    return fail(Error::format, "only MAXVAL 255 is supported");
  if (*depth == 4) {
    if (tupltype && *tupltype != "RGB_ALPHA")
      return fail(Error::format, "DEPTH 4 requires TUPLTYPE RGB_ALPHA");
  } else if (*depth == 3) {
    if (tupltype && *tupltype != "RGB")
      return fail(Error::format, "DEPTH 3 requires TUPLTYPE RGB");
  } else {
    return fail(Error::format,
                "only DEPTH 3 (RGB) or 4 (RGB_ALPHA) is supported");
  }
  h.width = *width;
  h.height = *height;
  h.depth = *depth;
  h.payload_offset = pos;
  return {};
}

// "P6" <ws> width <ws> height <ws> maxval <one whitespace byte> payload.
// '#' starts a comment that runs to the end of the line.
Result parse_p6(std::span<const std::uint8_t> bytes, Header &h) {
  std::size_t pos = 2;
  std::uint32_t values[3] = {};
  for (std::uint32_t &value : values) {
    bool saw_space = false;
    while (pos < bytes.size() && pos <= kMaxHeaderBytes) {
      if (is_space(bytes[pos])) {
        saw_space = true;
        ++pos;
      } else if (bytes[pos] == '#') {
        while (pos < bytes.size() && bytes[pos] != '\n')
          ++pos;
      } else {
        break;
      }
    }
    if (!saw_space || pos >= bytes.size() || pos > kMaxHeaderBytes)
      return fail(Error::format, "truncated or oversized PPM header");
    const std::size_t start = pos;
    while (pos < bytes.size() && bytes[pos] >= '0' && bytes[pos] <= '9')
      ++pos;
    auto parsed = parse_u32(std::string_view(
        reinterpret_cast<const char *>(bytes.data()) + start, pos - start));
    if (!parsed)
      return fail(Error::format, "invalid number in PPM header");
    value = *parsed;
  }
  if (pos >= bytes.size() || !is_space(bytes[pos]))
    return fail(Error::format, "PPM header must end with one whitespace byte");
  if (values[2] != 255)
    return fail(Error::format, "only maxval 255 is supported");
  h.width = values[0];
  h.height = values[1];
  h.depth = 3;
  h.payload_offset = pos + 1;
  return {};
}

} // namespace

Result decode(std::span<const std::uint8_t> bytes, Image &out) {
  Header h;
  if (bytes.size() >= 3 && bytes[0] == 'P' && bytes[1] == '7' &&
      bytes[2] == '\n') {
    if (Result r = parse_p7(bytes, h); !r)
      return r;
  } else if (bytes.size() >= 3 && bytes[0] == 'P' && bytes[1] == '6' &&
             is_space(bytes[2])) {
    if (Result r = parse_p6(bytes, h); !r)
      return r;
  } else {
    return fail(Error::format, "not a P7 PAM or P6 PPM file");
  }
  if (Result r = check_dimensions(h); !r)
    return r;
  // Bounded by kMaxPixels * 4, so this cannot overflow.
  const std::size_t payload = std::size_t{h.width} * h.height * h.depth;
  const std::size_t available = bytes.size() - h.payload_offset;
  if (available < payload)
    return fail(Error::format, "pixel data is truncated");
  if (available > payload)
    return fail(Error::format, "unexpected bytes after pixel data");
  Image image;
  if (Status s = Image::create(h.width, h.height, image); s != Status::ok)
    return fail(s == Status::out_of_memory ? Error::io : Error::limits,
                std::string("cannot allocate image: ") + status_name(s));
  const std::uint8_t *src = bytes.data() + h.payload_offset;
  for (std::uint32_t y = 0; y < h.height; ++y) {
    std::uint8_t *row = image.row(y);
    for (std::uint32_t x = 0; x < h.width; ++x) {
      std::uint8_t *px = row + std::size_t{x} * kChannels;
      px[0] = src[0];
      px[1] = src[1];
      px[2] = src[2];
      px[3] = h.depth == 4 ? src[3] : 255;
      src += h.depth;
    }
  }
  out = std::move(image);
  return {};
}

Result read_file(const std::string &path, Image &out) {
  // std::FILE reports read errors reliably through ferror (for example
  // EISDIR when the path is a directory), unlike std::ifstream.
  std::FILE *file = std::fopen(path.c_str(), "rb");
  if (file == nullptr)
    return fail(Error::io, "cannot open input file");
  // Upper bound for any acceptable file: header plus the largest payload.
  constexpr std::uint64_t max_bytes = kMaxHeaderBytes + kMaxPixels * kChannels;
  std::vector<std::uint8_t> bytes;
  std::uint8_t buffer[1 << 16];
  Result result;
  while (true) {
    const std::size_t got = std::fread(buffer, 1, sizeof buffer, file);
    if (bytes.size() + got > max_bytes) {
      result =
          fail(Error::limits, "input file is larger than any accepted image");
      break;
    }
    bytes.insert(bytes.end(), buffer, buffer + got);
    if (got < sizeof buffer) {
      if (std::ferror(file))
        result = fail(Error::io, "cannot read input file");
      break;
    }
  }
  std::fclose(file);
  if (!result)
    return result;
  return decode(bytes, out);
}

std::vector<std::uint8_t> encode(const ConstImageView &view) {
  if (validate_view(view) != Status::ok)
    return {};
  const std::string header =
      "P7\nWIDTH " + std::to_string(view.width) + "\nHEIGHT " +
      std::to_string(view.height) +
      "\nDEPTH 4\nMAXVAL 255\nTUPLTYPE RGB_ALPHA\nENDHDR\n";
  const std::size_t row_bytes = std::size_t{view.width} * kChannels;
  std::vector<std::uint8_t> bytes(header.begin(), header.end());
  bytes.reserve(bytes.size() + row_bytes * view.height);
  for (std::uint32_t y = 0; y < view.height; ++y) {
    const std::uint8_t *row = view.data + std::size_t{y} * view.stride;
    bytes.insert(bytes.end(), row, row + row_bytes);
  }
  return bytes;
}

Result write_file(const std::string &path, const ConstImageView &view) {
  const std::vector<std::uint8_t> bytes = encode(view);
  if (bytes.empty())
    return fail(Error::format, "invalid image view");
  namespace fs = std::filesystem;
#ifdef IMAGELAB_HAVE_MKSTEMP
  std::string temp = path + ".tmp-XXXXXX";
  const int fd = ::mkstemp(temp.data());
  if (fd < 0)
    return fail(Error::io, "cannot create temporary output file");
  // mkstemp creates mode 0600; give the result the usual 0666 & ~umask.
  // Reading the umask briefly changes it process-wide, which is fine for the
  // single-threaded CLI and tests that use this function.
  const mode_t mask = ::umask(0);
  ::umask(mask);
  bool ok = ::fchmod(fd, 0666 & ~mask) == 0;
  std::size_t done = 0;
  while (done < bytes.size()) {
    const ssize_t n = ::write(fd, bytes.data() + done, bytes.size() - done);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0) {
      ok = false;
      break;
    }
    done += static_cast<std::size_t>(n);
  }
  if (ok && ::fsync(fd) != 0)
    ok = false;
  if (::close(fd) != 0)
    ok = false;
#else
  const std::string temp = path + ".tmp-imagelab";
  bool ok = true;
  {
    std::ofstream out(temp, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char *>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
    out.flush();
    ok = static_cast<bool>(out);
  }
#endif
  std::error_code ec;
  if (!ok) {
    fs::remove(temp, ec);
    return fail(Error::io, "cannot write output file");
  }
  fs::rename(temp, path, ec);
  if (ec) {
    std::error_code ignored;
    fs::remove(temp, ignored);
    return fail(Error::io, "cannot rename temporary output file into place");
  }
  return {};
}

} // namespace imagelab::pam
