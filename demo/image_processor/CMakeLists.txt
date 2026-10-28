cmake_minimum_required(VERSION 3.20)
project(AegisImageLab VERSION 0.1.0 LANGUAGES CXX)

# AEGIS ImageLab: a controlled C++20 image-processing target for comparing
# baseline and protector-transformed builds. See README.md.

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(IMAGELAB_WERROR "Treat compiler warnings as errors" OFF)
option(IMAGELAB_SANITIZE
  "Build with ASan and UBSan (IR-variant kernel objects stay uninstrumented)" OFF)
option(IMAGELAB_ENABLE_IR_VARIANTS
  "Build kernel variants through LLVM IR (needs Clang and a matching opt)" ON)
set(IMAGELAB_IR_BACKEND_FLAGS "-O2" CACHE STRING
  "Flags used to compile every kernels IR variant to an object (list)")
set(IMAGELAB_SHIELD_PLUGIN "" CACHE FILEPATH
  "Path to AegisShield.so; when set, adds the 'shield' variant")
set(IMAGELAB_SHIELD_SEED "42" CACHE STRING "Shield seed (decimal uint64)")
set(IMAGELAB_SHIELD_MAX_SITES "64" CACHE STRING "Shield per-function budget")
set(IMAGELAB_EXTERNAL_KERNELS_IR "" CACHE FILEPATH
  "Externally transformed kernels IR (.ll/.bc); when set, adds the 'external' variant")

set(IMAGELAB_WARNINGS -Wall -Wextra -Wpedantic -Wshadow)
if(IMAGELAB_WERROR)
  list(APPEND IMAGELAB_WARNINGS -Werror)
endif()

# ---------------------------------------------------------------------------
# Common code: validation, drivers and codec. Never handed to a protector.
add_library(imagelab_common OBJECT src/image.cpp src/pam.cpp)
target_include_directories(imagelab_common PUBLIC include)
target_compile_options(imagelab_common PRIVATE ${IMAGELAB_WARNINGS})

if(IMAGELAB_SANITIZE)
  set(IMAGELAB_SAN_FLAGS -fsanitize=address,undefined -fno-sanitize-recover=all
      -fno-omit-frame-pointer)
  target_compile_options(imagelab_common PRIVATE ${IMAGELAB_SAN_FLAGS})
endif()

set(IMAGELAB_VARIANTS "")
set(IMAGELAB_VARIANT_JSON "")

# imagelab_add_variant(<name> <kernel source or object> [<ir file>])
# Builds lib, CLI, benchmark and unit tests for one kernel implementation.
# Executables go to <build>/<name>/.
function(imagelab_add_variant name kernel)
  set(ir "${ARGV2}")
  add_library(imagelab_${name} STATIC $<TARGET_OBJECTS:imagelab_common> ${kernel})
  target_include_directories(imagelab_${name} PUBLIC include)
  target_compile_options(imagelab_${name} PRIVATE ${IMAGELAB_WARNINGS})
  foreach(tool cli bench unit)
    if(tool STREQUAL "cli")
      set(src cli/main.cpp)
      set(out imagelab-cli)
    elseif(tool STREQUAL "bench")
      set(src bench/bench.cpp)
      set(out imagelab-bench)
    else()
      set(src tests/unit_tests.cpp)
      set(out imagelab-unit-tests)
    endif()
    set(target imagelab_${tool}_${name})
    add_executable(${target} ${src})
    target_link_libraries(${target} PRIVATE imagelab_${name})
    target_compile_options(${target} PRIVATE ${IMAGELAB_WARNINGS})
    target_compile_definitions(${target} PRIVATE IMAGELAB_VARIANT="${name}")
    set_target_properties(${target} PROPERTIES OUTPUT_NAME ${out}
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${name}")
    if(IMAGELAB_SANITIZE)
      target_compile_options(${target} PRIVATE ${IMAGELAB_SAN_FLAGS})
      target_link_options(${target} PRIVATE ${IMAGELAB_SAN_FLAGS})
    endif()
  endforeach()
  if(kernel MATCHES "\\.o$")
    set(object "\"${kernel}\"")
  else()
    set(object "\"$<TARGET_OBJECTS:imagelab_${name}>\"")
  endif()
  if(ir)
    set(ir_json "\"${ir}\"")
  else()
    set(ir_json "null")
  endif()
  set(entry "    {\"name\": \"${name}\", \"cli\": \"$<TARGET_FILE:imagelab_cli_${name}>\", \"bench\": \"$<TARGET_FILE:imagelab_bench_${name}>\", \"unit_tests\": \"$<TARGET_FILE:imagelab_unit_${name}>\", \"kernel_object\": ${object}, \"kernel_ir\": ${ir_json}}")
  if(IMAGELAB_VARIANT_JSON)
    set(entry ",\n${entry}")
  endif()
  set(IMAGELAB_VARIANT_JSON "${IMAGELAB_VARIANT_JSON}${entry}" PARENT_SCOPE)
  set(IMAGELAB_VARIANTS ${IMAGELAB_VARIANTS} ${name} PARENT_SCOPE)
endfunction()

# Native: kernels.cpp compiled with the normal flags of this build type.
set(kernels_native src/kernels.cpp)
if(IMAGELAB_SANITIZE)
  set_source_files_properties(src/kernels.cpp PROPERTIES
    COMPILE_OPTIONS "${IMAGELAB_SAN_FLAGS}")
endif()
imagelab_add_variant(native ${kernels_native})

# ---------------------------------------------------------------------------
# IR variants. Every one starts from the same kernels.input.ll and is
# compiled with the same IMAGELAB_IR_BACKEND_FLAGS, so the only difference
# between ir-baseline and a protected variant is the protector itself.
set(IMAGELAB_IR_DIR "${CMAKE_BINARY_DIR}/ir")
set(IMAGELAB_SHIELD_JSON "null")
if(IMAGELAB_ENABLE_IR_VARIANTS AND NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(WARNING "IR variants need Clang (found ${CMAKE_CXX_COMPILER_ID}); "
                  "building the native variant only")
  set(IMAGELAB_ENABLE_IR_VARIANTS OFF)
endif()
if(NOT IMAGELAB_ENABLE_IR_VARIANTS AND (IMAGELAB_SHIELD_PLUGIN OR IMAGELAB_EXTERNAL_KERNELS_IR))
  message(FATAL_ERROR "IMAGELAB_SHIELD_PLUGIN and IMAGELAB_EXTERNAL_KERNELS_IR "
                      "need IMAGELAB_ENABLE_IR_VARIANTS with Clang")
endif()

if(IMAGELAB_ENABLE_IR_VARIANTS)
  get_filename_component(clang_dir "${CMAKE_CXX_COMPILER}" REALPATH)
  get_filename_component(clang_dir "${clang_dir}" DIRECTORY)
  get_filename_component(clang_link_dir "${CMAKE_CXX_COMPILER}" DIRECTORY)
  find_program(IMAGELAB_OPT NAMES opt HINTS "${clang_dir}" "${clang_link_dir}"
               NO_DEFAULT_PATH)
  if(NOT IMAGELAB_OPT)
    message(FATAL_ERROR "IR variants need LLVM 'opt' next to ${CMAKE_CXX_COMPILER}; "
                        "set IMAGELAB_OPT or -DIMAGELAB_ENABLE_IR_VARIANTS=OFF")
  endif()
  execute_process(COMMAND "${IMAGELAB_OPT}" --version OUTPUT_VARIABLE opt_version
                  RESULT_VARIABLE opt_rc)
  string(REGEX MATCH "LLVM version ([0-9.]+)" _ "${opt_version}")
  if(NOT opt_rc EQUAL 0 OR NOT CMAKE_MATCH_1 STREQUAL CMAKE_CXX_COMPILER_VERSION)
    message(FATAL_ERROR "opt (${IMAGELAB_OPT}, LLVM '${CMAKE_MATCH_1}') does not "
                        "match clang ${CMAKE_CXX_COMPILER_VERSION}")
  endif()

  # Frontend: -O0 without optnone keeps additions free of nuw/nsw flags
  # (InstCombine at -O1 and above infers them from the bounded ranges). The
  # helpers are always_inline, so all arithmetic sits in the annotated
  # functions. SROA then removes the -O0 stack slots; it adds no flags.
  # Relative paths keep absolute build paths out of the IR and reports.
  add_custom_command(
    OUTPUT "${IMAGELAB_IR_DIR}/kernels.frontend.ll"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${IMAGELAB_IR_DIR}"
    COMMAND "${CMAKE_CXX_COMPILER}" -std=c++20 -O0 -Xclang -disable-O0-optnone
            -Iinclude -S -emit-llvm src/kernels.cpp
            -o "${IMAGELAB_IR_DIR}/kernels.frontend.ll"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    DEPENDS src/kernels.cpp include/imagelab/kernels.h
    COMMENT "ImageLab: kernels.cpp -> LLVM IR"
    VERBATIM)
  add_custom_command(
    OUTPUT "${IMAGELAB_IR_DIR}/kernels.input.ll"
    COMMAND "${IMAGELAB_OPT}" "-passes=function(sroa),verify" -S
            kernels.frontend.ll -o kernels.input.ll
    WORKING_DIRECTORY "${IMAGELAB_IR_DIR}"
    DEPENDS "${IMAGELAB_IR_DIR}/kernels.frontend.ll"
    COMMENT "ImageLab: prepare kernels.input.ll (protector input)"
    VERBATIM)

  # imagelab_ir_object(<name> <ir file>) -> ${IMAGELAB_IR_DIR}/kernels.<name>.o
  function(imagelab_ir_object name ir)
    add_custom_command(
      OUTPUT "${IMAGELAB_IR_DIR}/kernels.${name}.o"
      COMMAND "${CMAKE_CXX_COMPILER}" ${IMAGELAB_IR_BACKEND_FLAGS} -c "${ir}"
              -o "${IMAGELAB_IR_DIR}/kernels.${name}.o"
      DEPENDS "${ir}"
      COMMENT "ImageLab: ${name} kernels IR -> object"
      VERBATIM)
  endfunction()

  imagelab_ir_object(ir-baseline "${IMAGELAB_IR_DIR}/kernels.input.ll")
  imagelab_add_variant(ir-baseline "${IMAGELAB_IR_DIR}/kernels.ir-baseline.o"
                       "${IMAGELAB_IR_DIR}/kernels.input.ll")

  if(IMAGELAB_SHIELD_PLUGIN)
    if(NOT IMAGELAB_SHIELD_SEED MATCHES "^[0-9]+$" OR
       NOT IMAGELAB_SHIELD_MAX_SITES MATCHES "^[0-9]+$")
      message(FATAL_ERROR "IMAGELAB_SHIELD_SEED and IMAGELAB_SHIELD_MAX_SITES "
                          "must be decimal integers")
    endif()
    if(NOT EXISTS "${IMAGELAB_SHIELD_PLUGIN}")
      message(FATAL_ERROR "IMAGELAB_SHIELD_PLUGIN not found: ${IMAGELAB_SHIELD_PLUGIN}")
    endif()
    # The pipeline holds only relative names and digits, so no Shield
    # pipeline metacharacters can come from the build path.
    set(pipeline "aegis-shield<seed=${IMAGELAB_SHIELD_SEED}$<SEMICOLON>max-sites=${IMAGELAB_SHIELD_MAX_SITES}$<SEMICOLON>report=kernels.shield.report.json>,verify")
    add_custom_command(
      OUTPUT "${IMAGELAB_IR_DIR}/kernels.shield.ll"
             "${IMAGELAB_IR_DIR}/kernels.shield.report.json"
      COMMAND "${IMAGELAB_OPT}" -load-pass-plugin "${IMAGELAB_SHIELD_PLUGIN}"
              "-passes=${pipeline}" -S kernels.input.ll -o kernels.shield.ll
      WORKING_DIRECTORY "${IMAGELAB_IR_DIR}"
      DEPENDS "${IMAGELAB_IR_DIR}/kernels.input.ll" "${IMAGELAB_SHIELD_PLUGIN}"
      COMMENT "ImageLab: run aegis-shield on kernels.input.ll"
      VERBATIM)
    imagelab_ir_object(shield "${IMAGELAB_IR_DIR}/kernels.shield.ll")
    imagelab_add_variant(shield "${IMAGELAB_IR_DIR}/kernels.shield.o"
                         "${IMAGELAB_IR_DIR}/kernels.shield.ll")
    set(IMAGELAB_SHIELD_JSON "{\"plugin\": \"${IMAGELAB_SHIELD_PLUGIN}\", \"seed\": \"${IMAGELAB_SHIELD_SEED}\", \"max_sites\": ${IMAGELAB_SHIELD_MAX_SITES}, \"report\": \"${IMAGELAB_IR_DIR}/kernels.shield.report.json\"}")
  endif()

  if(IMAGELAB_EXTERNAL_KERNELS_IR)
    get_filename_component(external_ir "${IMAGELAB_EXTERNAL_KERNELS_IR}" ABSOLUTE)
    if(NOT EXISTS "${external_ir}")
      message(FATAL_ERROR "IMAGELAB_EXTERNAL_KERNELS_IR not found: ${external_ir}")
    endif()
    imagelab_ir_object(external "${external_ir}")
    imagelab_add_variant(external "${IMAGELAB_IR_DIR}/kernels.external.o"
                         "${external_ir}")
  endif()
endif()

message(STATUS "ImageLab variants: ${IMAGELAB_VARIANTS}")

# Machine-readable description of this build for tools/compare_variants.py.
file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/imagelab-variants.json" CONTENT
"{
  \"schema\": \"imagelab.variants.v1\",
  \"source_dir\": \"${CMAKE_CURRENT_SOURCE_DIR}\",
  \"build_type\": \"$<CONFIG>\",
  \"compiler_id\": \"${CMAKE_CXX_COMPILER_ID}\",
  \"compiler_version\": \"${CMAKE_CXX_COMPILER_VERSION}\",
  \"compiler\": \"${CMAKE_CXX_COMPILER}\",
  \"ir_backend_flags\": \"${IMAGELAB_IR_BACKEND_FLAGS}\",
  \"sanitize\": $<IF:$<BOOL:${IMAGELAB_SANITIZE}>,true,false>,
  \"shield\": ${IMAGELAB_SHIELD_JSON},
  \"variants\": [
${IMAGELAB_VARIANT_JSON}
  ]
}
")

# ---------------------------------------------------------------------------
# Tests
include(CTest)
if(BUILD_TESTING)
  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  set(py "${Python3_EXECUTABLE}")
  set(fixtures "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures")

  add_test(NAME imagelab.fixtures
    COMMAND "${py}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/make_fixtures.py"
            --check "${fixtures}")
  add_test(NAME imagelab.cli
    COMMAND "${py}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cli.py"
            --cli "$<TARGET_FILE:imagelab_cli_native>")
  foreach(variant IN LISTS IMAGELAB_VARIANTS)
    add_test(NAME imagelab.unit.${variant} COMMAND imagelab_unit_${variant})
    add_test(NAME imagelab.reference.${variant}
      COMMAND "${py}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_reference.py"
              --cli "$<TARGET_FILE:imagelab_cli_${variant}>" --fixtures "${fixtures}")
  endforeach()
  add_test(NAME imagelab.bench.smoke
    COMMAND imagelab_bench_native --width 37 --height 19 --samples 2 --warmup 0
            --repeat 1)

  if(IMAGELAB_ENABLE_IR_VARIANTS)
    add_test(NAME imagelab.annotations
      COMMAND "${py}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/check_ir.py" annotations
              --ir "${IMAGELAB_IR_DIR}/kernels.input.ll"
              --allowlist "${CMAKE_CURRENT_SOURCE_DIR}/protect.allowlist")
    add_test(NAME imagelab.compare
      COMMAND "${py}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/compare_variants.py"
              --build "${CMAKE_BINARY_DIR}" --quick
              --output "${CMAKE_BINARY_DIR}/compare-quick.json")
  endif()
  if(IMAGELAB_SHIELD_PLUGIN)
    add_test(NAME imagelab.shield
      COMMAND "${py}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/check_ir.py" shield
              --baseline "${IMAGELAB_IR_DIR}/kernels.input.ll"
              --transformed "${IMAGELAB_IR_DIR}/kernels.shield.ll"
              --report "${IMAGELAB_IR_DIR}/kernels.shield.report.json"
              --allowlist "${CMAKE_CURRENT_SOURCE_DIR}/protect.allowlist")
  endif()
endif()
