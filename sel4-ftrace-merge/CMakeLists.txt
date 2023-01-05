# set minimum cmake verision
cmake_minimum_required(VERSION 3.0.0)

# set project name
project(ftrace-merge)

# add executable
add_executable (ftrace-merge ftrace-merge.c)

# specify include dir
target_include_directories(ftrace-merge PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_compile_options(ftrace-merge PRIVATE ${FLAGS_WAR_AS_ERR} ${FLAGS_MEM_DBG})
target_link_options(ftrace-merge  PRIVATE ${LFLAGS_MEM_DBG})

# target install
install(TARGETS ftrace-merge RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
