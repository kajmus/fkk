cmake_minimum_required(VERSION 3.20)
project(fileguard C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -g)

find_program(CLANG_PROG clang REQUIRED)
find_program(BPFTOOL_PROG bpftool REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)
find_package(ZLIB REQUIRED)
find_library(LIBELF_LIB elf REQUIRED)

# 2. Wykrywanie architektury pod kątem eBPF
execute_process(
    COMMAND uname -m
    OUTPUT_VARIABLE ARCH_RAW
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(ARCH_RAW STREQUAL "x86_64")
    set(BPF_TARGET_ARCH "x86")
elseif(ARCH_RAW STREQUAL "aarch64")
    set(BPF_TARGET_ARCH "arm64")
else()
    set(BPF_TARGET_ARCH ${ARCH_RAW})
endif()

# 3. Katalog na wygenerowane pliki eBPF
set(BPF_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/bpf_generated)
file(MAKE_DIRECTORY ${BPF_GEN_DIR})

# 4. Generowanie vmlinux.h
set(VMLINUX_H ${BPF_GEN_DIR}/vmlinux.h)
add_custom_command(
    OUTPUT ${VMLINUX_H}
    COMMAND ${BPFTOOL_PROG} btf dump file /sys/kernel/btf/vmlinux format c > ${VMLINUX_H}
    VERBATIM
    COMMENT "Generowanie vmlinux.h z jądra..."
)

# 5. Kompilacja plików .bpf.c do .bpf.o oraz .skel.h
file(GLOB BPF_SOURCES src/bpf/*.bpf.c)
set(BPF_SKELETON_HEADERS "")

foreach(BPF_SRC ${BPF_SOURCES})
    get_filename_component(BPF_NAME ${BPF_SRC} NAME_WE)
    
    set(BPF_OBJ ${BPF_GEN_DIR}/${BPF_NAME}.bpf.o)
    set(BPF_SKEL ${BPF_GEN_DIR}/${BPF_NAME}.skel.h)

    add_custom_command(
        OUTPUT ${BPF_OBJ}
        COMMAND ${CLANG_PROG} -g -O2 -target bpf 
                -D__TARGET_ARCH_${BPF_TARGET_ARCH}
                -I${BPF_GEN_DIR} 
                -I${CMAKE_CURRENT_SOURCE_DIR}/include 
                -c ${BPF_SRC} -o ${BPF_OBJ}
        DEPENDS ${BPF_SRC} ${VMLINUX_H}
        VERBATIM
        COMMENT "Kompilacja eBPF: ${BPF_SRC} -> ${BPF_NAME}.bpf.o"
    )

    add_custom_command(
        OUTPUT ${BPF_SKEL}
        COMMAND ${BPFTOOL_PROG} gen skeleton ${BPF_OBJ} > ${BPF_SKEL}
        DEPENDS ${BPF_OBJ}
        VERBATIM
        COMMENT "Generowanie skeletonu C: ${BPF_NAME}.skel.h"
    )

    list(APPEND BPF_SKELETON_HEADERS ${BPF_SKEL})
endforeach()

# Sztuczny cel grupujący nagłówki .skel.h
add_custom_target(generate_bpf_skeletons DEPENDS ${BPF_SKELETON_HEADERS})

# 6. Kompilacja głównej aplikacji User Space
file(GLOB APP_SOURCES 
    src/main.c
    src/cli/*.c
)

add_executable(fileguard ${APP_SOURCES})

# Ustawienie ścieżek wyszukiwania nagłówków (#include)
target_include_directories(fileguard PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${BPF_GEN_DIR}
)

# Linkowanie bibliotek
target_link_libraries(fileguard PRIVATE
    ${LIBBPF_LIBRARIES}
    ${LIBELF_LIB}
    ZLIB::ZLIB
)

# Wymuszenie kolejności: najpierw eBPF (.skel.h), potem kod C
add_dependencies(fileguard generate_bpf_skeletons)