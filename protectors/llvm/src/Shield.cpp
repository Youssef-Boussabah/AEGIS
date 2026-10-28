#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Plugins/PassPlugin.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

using namespace llvm;

namespace {
constexpr StringLiteral Annotation = "aegis.protect";
constexpr StringLiteral Marker = "aegis.shield.generated";

[[noreturn]] void fail(const Twine &Message) {
  report_fatal_error(Twine("aegis-shield: ") + Message, false);
}

struct Config {
  uint64_t Seed = 0;
  unsigned MaxSites = 16;
  bool Enabled = true;
  std::string Report;
};

uint64_t decimal(StringRef Text, StringRef Key) {
  uint64_t Result;
  if (Text.empty() || Text.find_first_not_of("0123456789") != StringRef::npos ||
      Text.getAsInteger(10, Result))
    fail(Twine("invalid unsigned decimal for ") + Key);
  return Result;
}

unsigned maxSites(uint64_t N) {
  if (N > 1000000)
    fail("max-sites must be in [0, 1000000]");
  return static_cast<unsigned>(N);
}

void readConfig(StringRef Path, Config &C) {
  auto Buffer = MemoryBuffer::getFile(Path);
  if (!Buffer)
    fail(Twine("cannot read config: ") + Buffer.getError().message());
  auto Parsed = json::parse((*Buffer)->getBuffer());
  if (!Parsed)
    fail(Twine("invalid config JSON: ") + toString(Parsed.takeError()));
  const auto *Object = Parsed->getAsObject();
  if (!Object)
    fail("config must be an object");
  auto Version = Object->getInteger("schema_version");
  if (!Version || *Version != 1)
    fail("config schema_version must be 1");
  for (const auto &[Key, Value] : *Object) {
    if (Key == "schema_version")
      continue;
    if (Key == "seed") {
      auto S = Value.getAsString();
      if (!S)
        fail("config seed must be a decimal string");
      C.Seed = decimal(*S, "seed");
    } else if (Key == "max_sites_per_function") {
      auto N = Value.getAsInteger();
      if (!N || *N < 0)
        fail("config max_sites_per_function must be a nonnegative integer");
      C.MaxSites = maxSites(static_cast<uint64_t>(*N));
    } else if (Key == "enabled") {
      auto B = Value.getAsBoolean();
      if (!B)
        fail("config enabled must be boolean");
      C.Enabled = *B;
    } else {
      fail(Twine("unknown config key: ") + StringRef(Key));
    }
  }
}

Config parseConfig(StringRef Name) {
  Config C;
  if (Name == "aegis-shield")
    return C;
  auto Body = Name.drop_front(StringRef("aegis-shield<").size()).drop_back();
  if (Body.empty())
    fail("empty options; use aegis-shield without angle brackets for defaults");
  SmallVector<StringRef> Parts;
  Body.split(Parts, ';', -1, true);
  std::map<std::string, std::string> Options;
  for (StringRef Part : Parts) {
    auto [Key, Value] = Part.split('=');
    if (Value.empty() ||
        (Key != "seed" && Key != "max-sites" && Key != "enabled" &&
         Key != "config" && Key != "report"))
      fail(Twine("invalid option: ") + Part);
    if (!Options.emplace(Key.str(), Value.str()).second)
      fail(Twine("duplicate option: ") + Key);
  }
  if (Options.contains("config"))
    readConfig(Options.at("config"), C);
  if (Options.contains("seed"))
    C.Seed = decimal(Options.at("seed"), "seed");
  if (Options.contains("max-sites"))
    C.MaxSites = maxSites(decimal(Options.at("max-sites"), "max-sites"));
  if (Options.contains("enabled")) {
    StringRef V = Options.at("enabled");
    if (V != "true" && V != "false")
      fail("enabled must be true or false");
    C.Enabled = V == "true";
  }
  if (Options.contains("report"))
    C.Report = Options.at("report");
  return C;
}

// Specified fixed-width arithmetic, independent of std::hash and host RNGs.
uint64_t mix(uint64_t X) {
  X += UINT64_C(0x9e3779b97f4a7c15);
  X = (X ^ (X >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
  X = (X ^ (X >> 27)) * UINT64_C(0x94d049bb133111eb);
  return X ^ (X >> 31);
}

uint64_t functionKey(StringRef Name, uint64_t Seed) {
  uint64_t H = UINT64_C(14695981039346656037);
  for (unsigned char Byte : Name.bytes()) {
    H ^= Byte;
    H *= UINT64_C(1099511628211);
  }
  return mix(H ^ Seed);
}

SmallPtrSet<Function *, 16> annotatedFunctions(Module &M) {
  SmallPtrSet<Function *, 16> Result;
  for (Function &F : M)
    if (F.hasFnAttribute(Annotation))
      Result.insert(&F);
  auto *Annotations = M.getNamedGlobal("llvm.global.annotations");
  if (!Annotations || !Annotations->hasInitializer())
    return Result;
  auto *Array = dyn_cast<ConstantArray>(Annotations->getInitializer());
  if (!Array)
    return Result;
  for (const Use &Entry : Array->operands()) {
    auto *Record = dyn_cast<ConstantStruct>(Entry.get());
    if (!Record || Record->getNumOperands() < 2)
      continue;
    auto *F = dyn_cast<Function>(Record->getOperand(0)->stripPointerCasts());
    StringRef Text;
    if (F && getConstantStringInfo(Record->getOperand(1), Text) &&
        Text == Annotation)
      Result.insert(F);
  }
  return Result;
}

bool integerSignature(const Function &F) {
  return !F.isVarArg() && F.getReturnType()->isIntegerTy() &&
         llvm::all_of(F.args(), [](const Argument &A) {
           return A.getType()->isIntegerTy();
         });
}

void writeReport(StringRef Path, json::Object Report) {
  if (Path.empty())
    return;
  int FD;
  SmallString<256> Temporary;
  if (auto E =
          sys::fs::createUniqueFile(Twine(Path) + ".tmp-%%%%%%", FD, Temporary))
    fail(Twine("cannot create report: ") + E.message());
  raw_fd_ostream OS(FD, true);
  OS << formatv("{0:2}\n", json::Value(std::move(Report)));
  OS.close();
  if (OS.has_error()) {
    auto E = OS.error();
    OS.clear_error();
    sys::fs::remove(Temporary);
    fail(Twine("cannot write report: ") + E.message());
  }
  if (auto E = sys::fs::rename(Temporary, Path)) {
    sys::fs::remove(Temporary);
    fail(Twine("cannot publish report: ") + E.message());
  }
}

struct Candidate {
  BinaryOperator *Add;
  uint64_t Index;
  uint64_t Rank;
};

class ShieldPass : public PassInfoMixin<ShieldPass> {
  Config C;

public:
  explicit ShieldPass(Config C) : C(std::move(C)) {}

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    auto Annotated = annotatedFunctions(M);
    json::Array Functions;
    uint64_t Total = 0;
    for (Function &F : M) {
      const bool Selected = Annotated.contains(&F);
      json::Object Row{{"name", F.getName()}, {"annotated", Selected}};
      json::Array Sites;
      json::Object Skips;
      std::string Reason;
      std::vector<Candidate> Candidates;
      if (!Selected)
        Reason = "not-annotated";
      else if (!C.Enabled)
        Reason = "disabled";
      else if (F.isDeclaration())
        Reason = "declaration";
      else if (!integerSignature(F))
        Reason = "unsupported-signature";
      else if (F.hasFnAttribute(Attribute::OptimizeNone))
        Reason = "optnone";
      else {
        std::map<std::string, int64_t> Counts;
        uint64_t Index = 0;
        const uint64_t Key = functionKey(F.getName(), C.Seed);
        for (Instruction &I : instructions(F)) {
          auto *Add = dyn_cast<BinaryOperator>(&I);
          if (!Add || Add->getOpcode() != Instruction::Add)
            continue;
          const uint64_t Current = Index++;
          if (Add->getMetadata(Marker))
            ++Counts["already-generated"];
          else if (!Add->getType()->isIntegerTy() ||
                   Add->getType()->getIntegerBitWidth() < 2 ||
                   Add->getType()->getIntegerBitWidth() > 128)
            ++Counts["unsupported-type"];
          else if (Add->hasNoSignedWrap() || Add->hasNoUnsignedWrap())
            ++Counts["overflow-flags"];
          else if (isa<UndefValue>(Add->getOperand(0)) ||
                   isa<UndefValue>(Add->getOperand(1)))
            ++Counts["undef-or-poison"];
          else
            Candidates.push_back({Add, Current, mix(Key ^ Current)});
        }
        std::sort(Candidates.begin(), Candidates.end(), [](auto &A, auto &B) {
          return A.Rank != B.Rank ? A.Rank < B.Rank : A.Index < B.Index;
        });
        if (Candidates.size() > C.MaxSites) {
          Counts["budget"] = Candidates.size() - C.MaxSites;
          Candidates.resize(C.MaxSites);
        }
        std::sort(Candidates.begin(), Candidates.end(),
                  [](auto &A, auto &B) { return A.Index < B.Index; });
        for (const auto &[Why, N] : Counts)
          Skips[Why] = N;
        Reason = Candidates.empty() ? "no-eligible-sites" : "expanded";
      }
      for (const Candidate &Site : Candidates) {
        auto *Add = Site.Add;
        IRBuilder<NoFolder> B(Add);
        B.SetCurrentDebugLocation(Add->getDebugLoc());
        // Freeze inputs before duplicating uses, choosing a consistent value
        // for each operand. This is an LLVM refinement for poison/undef;
        // defined inputs are unchanged. Repeated operands share the same
        // freeze.
        auto *A = B.CreateFreeze(Add->getOperand(0), "aegis.a");
        auto *D = Add->getOperand(0) == Add->getOperand(1)
                      ? A
                      : B.CreateFreeze(Add->getOperand(1), "aegis.b");
        Value *Replacement;
        StringRef Variant;
        if ((Site.Rank & 1) == 0) {
          auto *X = B.CreateXor(A, D, "aegis.xor");
          auto *Carry = B.CreateAnd(A, D, "aegis.carry");
          auto *Shift = B.CreateShl(Carry, 1, "aegis.shift");
          Replacement = B.CreateAdd(X, Shift);
          Variant = "xor-carry";
        } else {
          auto *O = B.CreateOr(A, D, "aegis.or");
          auto *Carry = B.CreateAnd(A, D, "aegis.carry");
          Replacement = B.CreateAdd(O, Carry);
          Variant = "or-carry";
        }
        // Tag every generated instruction so immediate repeated pass runs do
        // not recursively expand the generated adds.
        for (auto It = cast<Instruction>(A)->getIterator(); &*It != Add; ++It)
          It->setMetadata(Marker, MDNode::get(M.getContext(), {}));
        Replacement->takeName(Add);
        Add->replaceAllUsesWith(Replacement);
        Sites.push_back(
            json::Object{{"add_index", Site.Index},
                         {"bit_width", Add->getType()->getIntegerBitWidth()},
                         {"variant", Variant}});
        Add->eraseFromParent();
        ++Total;
      }
      Row["status"] = Candidates.empty() ? "skipped" : "transformed";
      Row["reason"] = Reason;
      Row["transformed_sites"] = std::move(Sites);
      Row["skipped_adds"] = std::move(Skips);
      Functions.push_back(std::move(Row));
    }
    writeReport(
        C.Report,
        json::Object{
            {"schema_version", 1},
            {"backend", "aegis-shield-llvm"},
            {"llvm_version", LLVM_VERSION_STRING},
            {"module", M.getModuleIdentifier()},
            {"config", json::Object{{"seed", std::to_string(C.Seed)},
                                    {"max_sites_per_function", C.MaxSites},
                                    {"enabled", C.Enabled}}},
            {"transformed_sites", Total},
            {"functions", std::move(Functions)}});
    return Total ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }
};
} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
      LLVM_PLUGIN_API_VERSION, "AegisShield", "0.1.0", [](PassBuilder &PB) {
        PB.registerPipelineParsingCallback(
            [](StringRef Name, ModulePassManager &MPM,
               ArrayRef<PassBuilder::PipelineElement> Inner) {
              if (Name != "aegis-shield" &&
                  !(Name.starts_with("aegis-shield<") && Name.ends_with(">")))
                return false;
              if (!Inner.empty())
                fail("nested pipelines are not supported");
              MPM.addPass(ShieldPass(parseConfig(Name)));
              return true;
            });
      }};
}
