// imagelab-cli: command-line front end for AEGIS ImageLab.
//
//   imagelab-cli tone    [--exposure-q8 N] [--knee N] INPUT OUTPUT
//   imagelab-cli color   [--saturation-q8 N] [--contrast-q8 N]
//                        [--brightness N] INPUT OUTPUT
//   imagelab-cli enhance [--amount-q8 N] [--threshold N] INPUT OUTPUT
//   imagelab-cli info    INPUT
//   imagelab-cli --help | --version
//
// Exit codes: 0 success, 1 internal error, 2 usage error, 3 I/O error,
// 4 invalid image file, 5 parameter out of range, 6 image exceeds limits.

#include "imagelab/imagelab.hpp"
#include "imagelab/pam.hpp"

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#ifndef IMAGELAB_VARIANT
#define IMAGELAB_VARIANT "unspecified"
#endif

namespace {

enum Exit : int {
  kOk = 0,
  kInternal = 1,
  kUsage = 2,
  kIo = 3,
  kFormat = 4,
  kParameter = 5,
  kLimits = 6,
};

constexpr const char *kUsageText =
    "usage:\n"
    "  imagelab-cli tone    [--exposure-q8 N] [--knee N] INPUT OUTPUT\n"
    "  imagelab-cli color   [--saturation-q8 N] [--contrast-q8 N] "
    "[--brightness N] INPUT OUTPUT\n"
    "  imagelab-cli enhance [--amount-q8 N] [--threshold N] INPUT OUTPUT\n"
    "  imagelab-cli info    INPUT\n"
    "  imagelab-cli --help | --version\n"
    "INPUT: P7 PAM (RGB or RGB_ALPHA) or P6 PPM, 8-bit. "
    "OUTPUT: P7 PAM RGB_ALPHA.\n";

int usage_error(const std::string &message) {
  std::fprintf(stderr, "imagelab-cli: %s\n%s", message.c_str(), kUsageText);
  return kUsage;
}

struct Args {
  std::string command;
  std::map<std::string, std::string> options;
  std::vector<std::string> positional;
};

// Splits argv into options ("--name value") and positional arguments.
// "--" ends option parsing. Each option may appear at most once.
std::optional<std::string> split_args(int argc, char **argv, Args &args) {
  args.command = argv[1];
  bool options_done = false;
  for (int i = 2; i < argc; ++i) {
    const std::string_view arg = argv[i];
    if (!options_done && arg == "--") {
      options_done = true;
    } else if (!options_done && arg.starts_with("--")) {
      if (i + 1 >= argc)
        return "option " + std::string(arg) + " needs a value";
      if (!args.options.emplace(std::string(arg), argv[i + 1]).second)
        return "option " + std::string(arg) + " given more than once";
      ++i;
    } else {
      args.positional.emplace_back(arg);
    }
  }
  return std::nullopt;
}

// Strict decimal integer: optional '-', then 1-18 digits.
std::optional<std::int64_t> parse_int(std::string_view text) {
  bool negative = false;
  if (!text.empty() && text.front() == '-') {
    negative = true;
    text.remove_prefix(1);
  }
  if (text.empty() || text.size() > 18)
    return std::nullopt;
  std::int64_t value = 0;
  for (char c : text) {
    if (c < '0' || c > '9')
      return std::nullopt;
    value = value * 10 + (c - '0');
  }
  return negative ? -value : value;
}

class OptionReader {
public:
  explicit OptionReader(Args &args) : args_(args) {}

  // Reads an option into *out. Returns an exit code, or kOk.
  template <typename T>
  int read(const std::string &name, std::int64_t lo, std::int64_t hi, T &out) {
    auto it = args_.options.find(name);
    if (it == args_.options.end())
      return kOk;
    const auto value = parse_int(it->second);
    args_.options.erase(it);
    if (!value) {
      std::fprintf(stderr, "imagelab-cli: %s expects a decimal integer\n",
                   name.c_str());
      return kUsage;
    }
    if (*value < lo || *value > hi) {
      std::fprintf(stderr,
                   "imagelab-cli: %s must be in [%" PRId64 ", %" PRId64 "]\n",
                   name.c_str(), lo, hi);
      return kParameter;
    }
    out = static_cast<T>(*value);
    return kOk;
  }

  int finish() const {
    if (args_.options.empty())
      return kOk;
    return usage_error("unknown option " + args_.options.begin()->first);
  }

private:
  Args &args_;
};

int io_exit(const imagelab::pam::Result &r, const char *what,
            const std::string &path) {
  std::fprintf(stderr, "imagelab-cli: %s %s: %s\n", what, path.c_str(),
               r.message.c_str());
  switch (r.error) {
  case imagelab::pam::Error::none:
    return kOk;
  case imagelab::pam::Error::io:
    return kIo;
  case imagelab::pam::Error::format:
    return kFormat;
  case imagelab::pam::Error::limits:
    return kLimits;
  }
  return kInternal;
}

int status_exit(imagelab::Status s) {
  std::fprintf(stderr, "imagelab-cli: operation failed: %s\n",
               imagelab::status_name(s));
  return s == imagelab::Status::invalid_parameter ? kParameter : kInternal;
}

int run_info(const Args &args) {
  if (args.positional.size() != 1)
    return usage_error("info takes exactly one INPUT");
  imagelab::Image image;
  if (auto r = imagelab::pam::read_file(args.positional[0], image); !r)
    return io_exit(r, "cannot read", args.positional[0]);
  std::printf(
      "width=%" PRIu32 " height=%" PRIu32 " fingerprint=%016" PRIx64 "\n",
      image.width(), image.height(), imagelab::fingerprint(image.view()));
  return kOk;
}

int run_operation(Args &args) {
  OptionReader options(args);
  imagelab::ToneMapParams tone;
  imagelab::ColorParams color;
  imagelab::EnhanceParams enh;
  constexpr std::int64_t big = std::numeric_limits<std::uint32_t>::max();
  int rc = kOk;
  // Options are parsed with wide bounds here; the library's validate()
  // applies the documented ranges so the CLI cannot drift from the API.
  if (args.command == "tone") {
    if ((rc = options.read("--exposure-q8", 0, big, tone.exposure_q8)) ||
        (rc = options.read("--knee", 0, big, tone.knee)))
      return rc;
  } else if (args.command == "color") {
    if ((rc = options.read("--saturation-q8", 0, big, color.saturation_q8)) ||
        (rc = options.read("--contrast-q8", 0, big, color.contrast_q8)) ||
        (rc = options.read(
             "--brightness", std::numeric_limits<std::int32_t>::min(),
             std::numeric_limits<std::int32_t>::max(), color.brightness)))
      return rc;
  } else {
    if ((rc = options.read("--amount-q8", 0, big, enh.amount_q8)) ||
        (rc = options.read("--threshold", 0, big, enh.threshold)))
      return rc;
  }
  if ((rc = options.finish()))
    return rc;
  if (args.positional.size() != 2)
    return usage_error(args.command + " takes INPUT and OUTPUT");
  const std::string &input = args.positional[0];
  const std::string &output = args.positional[1];

  imagelab::Status param_status = imagelab::Status::ok;
  if (args.command == "tone")
    param_status = imagelab::validate(tone);
  else if (args.command == "color")
    param_status = imagelab::validate(color);
  else
    param_status = imagelab::validate(enh);
  if (param_status != imagelab::Status::ok)
    return status_exit(param_status);

  std::error_code ec;
  if (std::filesystem::exists(output, ec) &&
      std::filesystem::equivalent(input, output, ec))
    return usage_error("OUTPUT must not be the INPUT file");

  imagelab::Image src;
  if (auto r = imagelab::pam::read_file(input, src); !r)
    return io_exit(r, "cannot read", input);
  imagelab::Image dst;
  if (auto s = imagelab::Image::create(src.width(), src.height(), dst);
      s != imagelab::Status::ok)
    return status_exit(s);

  imagelab::Status s = imagelab::Status::ok;
  if (args.command == "tone")
    s = imagelab::tone_map(src.view(), dst.view(), tone);
  else if (args.command == "color")
    s = imagelab::adjust_color(src.view(), dst.view(), color);
  else
    s = imagelab::enhance(src.view(), dst.view(), enh);
  if (s != imagelab::Status::ok)
    return status_exit(s);

  if (auto r = imagelab::pam::write_file(output, dst.view()); !r)
    return io_exit(r, "cannot write", output);
  return kOk;
}

} // namespace

int main_impl(int argc, char **argv) {
  if (argc < 2)
    return usage_error("missing command");
  const std::string_view first = argv[1];
  if (first == "--help" || first == "-h") {
    std::fputs(kUsageText, stdout);
    return kOk;
  }
  if (first == "--version") {
    std::printf("imagelab-cli 0.1.0 (kernels: %s)\n", IMAGELAB_VARIANT);
    return kOk;
  }
  Args args;
  if (auto error = split_args(argc, argv, args))
    return usage_error(*error);
  if (args.command == "info") {
    if (!args.options.empty())
      return usage_error("info takes no options");
    return run_info(args);
  }
  if (args.command == "tone" || args.command == "color" ||
      args.command == "enhance")
    return run_operation(args);
  return usage_error("unknown command " + args.command);
}

int main(int argc, char **argv) {
  try {
    return main_impl(argc, argv);
  } catch (const std::exception &e) {
    std::fprintf(stderr, "imagelab-cli: internal error: %s\n", e.what());
  } catch (...) {
    std::fprintf(stderr, "imagelab-cli: internal error\n");
  }
  return kInternal;
}
