# set minimum cmake verision
cmake_minimum_required(VERSION 3.0.0)

# set project name
project(sel4-extract)

# add executable
add_executable (sel4-extract sel4-extract.c)

target_compile_options(sel4-extract PRIVATE ${FLAGS_WAR_AS_ERR} ${FLAGS_MEM_DBG})
target_link_options(sel4-extract  PRIVATE ${LFLAGS_MEM_DBG})

# target install
install(TARGETS sel4-extract RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
