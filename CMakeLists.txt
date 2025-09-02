cmake_minimum_required(VERSION 3.20)
project(avian_lwma LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(pybind11 REQUIRED)

add_library(_core MODULE
  src/avian_lwma_pybind.cpp
  src/lwma.cpp
)

target_include_directories(_core PRIVATE src)
target_link_libraries(_core PRIVATE pybind11::module)

if(NOT CMAKE_BUILD_TYPE MATCHES Debug)
  if (MSVC)
    target_compile_options(_core PRIVATE /O2)
  else()
    target_compile_options(_core PRIVATE -O3)
  endif()
endif()

set_target_properties(_core PROPERTIES PREFIX "" OUTPUT_NAME "_core")

install(TARGETS _core LIBRARY DESTINATION avian_lwma)
install(FILES python/avian_lwma/__init__.py DESTINATION avian_lwma)
install(FILES README.md LICENSE DESTINATION .)
