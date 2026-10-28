cmake_minimum_required(VERSION 3.20)
project(AegisShieldLLVM VERSION 0.1.0 LANGUAGES C CXX)
if(POLICY CMP0219)
  cmake_policy(SET CMP0219 NEW)
endif()

find_package(LLVM REQUIRED CONFIG)
if(LLVM_VERSION_MAJOR LESS 22)
  message(FATAL_ERROR "AEGIS Shield requires LLVM 22 or newer; tested with 22.1.8")
endif()
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)
include(HandleLLVMOptions)

add_llvm_pass_plugin(AegisShield src/Shield.cpp)
target_compile_features(AegisShield PRIVATE cxx_std_20)
target_include_directories(AegisShield SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})
separate_arguments(AEGIS_LLVM_DEFINITIONS NATIVE_COMMAND "${LLVM_DEFINITIONS}")
target_compile_options(AegisShield PRIVATE ${AEGIS_LLVM_DEFINITIONS})
set_target_properties(AegisShield PROPERTIES CXX_EXTENSIONS OFF)

include(CTest)
if(BUILD_TESTING)
  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  find_program(AEGIS_OPT NAMES opt HINTS "${LLVM_TOOLS_BINARY_DIR}" NO_DEFAULT_PATH REQUIRED)
  find_program(AEGIS_CLANG NAMES clang HINTS "${LLVM_TOOLS_BINARY_DIR}" NO_DEFAULT_PATH REQUIRED)
  add_test(NAME shield.integration COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_shield.py"
    --plugin "$<TARGET_FILE:AegisShield>" --opt "${AEGIS_OPT}"
    --clang "${AEGIS_CLANG}")
endif()
