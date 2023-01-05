# set minimum cmake verision
cmake_minimum_required(VERSION 3.0.0)

include(GNUInstallDirs)

# set project name
project(sel4-trace-support)

# set compiler options
set(FLAGS_WAR_AS_ERR -Wall -Wpedantic -Werror)

option(MEM_DBG "Debug memory with fsanitize" OFF)
if(MEM_DBG)
	set(FLAGS_MEM_DBG -fsanitize=address -fsanitize=leak -fsanitize=bounds)
	set(LFLAGS_MEM_DBG -fsanitize=address -fsanitize=bounds)
endif(MEM_DBG)
unset(MEM_DBG CACHE)

add_subdirectory(sel4-extract)
add_subdirectory(sel4-ftrace-merge)
