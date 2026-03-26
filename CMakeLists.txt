cmake_minimum_required(VERSION 3.16)
project(network_server_service C)

set(CMAKE_C_STANDARD 11)

# --- Apple Silicon (macOS ARM64) Homebrew Support ---
# Homebrew puts libraries here; CMake needs a hint to find them natively.
include_directories(/opt/homebrew/include)
link_directories(/opt/homebrew/lib)

include_directories(${CMAKE_SOURCE_DIR}/include)

add_executable(server_app
  main.c
  protocol.c
  src/user_db.c
)

find_package(Threads REQUIRED)

# Force the exact linker flags from your v0.1 manual build.
# Order matters: gdbm_compat must come before gdbm.
target_link_libraries(server_app Threads::Threads -lgdbm_compat -lgdbm)

if (EXISTS "${CMAKE_SOURCE_DIR}/src/db_test.c")
  add_executable(db_test
    src/db_test.c
    src/user_db.c
  )
  target_link_libraries(db_test Threads::Threads -lgdbm_compat -lgdbm)
endif()
