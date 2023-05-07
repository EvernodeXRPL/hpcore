# ##
# Compile-time timestamping library
#

# Adapted from https://github.com/kraiskil/cmake_timestamp
# This is only used for the HotPocket kill switch.

# CMake 3.12 made using OBJECT libraries much nicer, so we use that.
cmake_minimum_required(VERSION 3.12)

# Set CMake variable BUILD_TIME to 'now'. This 'now' is the time
# when CMake is run, not when the target builder (e.g. make) is run.
string(TIMESTAMP BUILD_TIME "%s" UTC)

# Compile the library that contains the global variables
add_library(killswitch OBJECT killswitch.c)
target_compile_definitions(
	killswitch
	PRIVATE -DBUILD_TIME="${BUILD_TIME}"
)
target_include_directories(killswitch
	PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

# Add a dummy target that removes the CMake variable BUILD_TIME from CMake's cache.
# this forces CMake to be-rerun when we hit this target.
add_custom_target(
	clear_cache
	COMMAND ${CMAKE_COMMAND} -U BUILD_TIME ${CMAKE_BINARY_DIR}
)

# Have the cache clearing be run before trying to build the killswitch library.
# This (I think) is the same as a PRE_BUILD custom_command. But PRE_BUILD is
# available for VS generators only, on others it is synonymous to PRE_LINK,
# i.e. "post compile"
add_dependencies(killswitch clear_cache)
