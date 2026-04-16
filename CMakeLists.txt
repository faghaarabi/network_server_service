cmake_minimum_required(VERSION 3.16)
project(network_server_service C)

set(CMAKE_C_STANDARD 11)

# Enable standard warnings for cleaner cross-platform compiling
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")

include_directories(${CMAKE_SOURCE_DIR}/include)

# --- OS-Specific Database Library Linking ---
if(APPLE)
    # Handle Apple Silicon (macOS ARM64) Homebrew Support
    if(EXISTS "/opt/homebrew/include")
        include_directories(/opt/homebrew/include)
        link_directories(/opt/homebrew/lib)
    endif()
    
    # Handle Intel Mac (macOS x86_64) Homebrew Support
    if(EXISTS "/usr/local/include")
        include_directories(/usr/local/include)
        link_directories(/usr/local/lib)
    endif()
    
    set(DB_LIBS gdbm_compat gdbm)
elseif(CMAKE_SYSTEM_NAME MATCHES "(?i)freebsd")
    # FreeBSD natively includes ndbm in libc; no extra links needed
    set(DB_LIBS "")
else()
    # Linux (Debian/Ubuntu/Fedora) requires gdbm packages
    set(DB_LIBS gdbm_compat gdbm)
endif()

add_executable(server_app
  main.c
  protocol.c
  src/user_db.c
  src/message_db.c   # <-- ADDED for v0.3 Message History
)

find_package(Threads REQUIRED)

# Safely link the determined database libraries
if(DB_LIBS)
    target_link_libraries(server_app Threads::Threads ${DB_LIBS})
else()
    target_link_libraries(server_app Threads::Threads)
endif()

if (EXISTS "${CMAKE_SOURCE_DIR}/src/db_test.c")
  add_executable(db_test
    src/db_test.c
    src/user_db.c
    src/message_db.c # <-- ADDED here as well
  )
  
  if(DB_LIBS)
      target_link_libraries(db_test Threads::Threads ${DB_LIBS})
  else()
      target_link_libraries(db_test Threads::Threads)
  endif()
endif()
