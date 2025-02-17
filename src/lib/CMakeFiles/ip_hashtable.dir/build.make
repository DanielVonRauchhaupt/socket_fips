# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.25

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /mnt/scratch/signer/master/fips-ipc

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /mnt/scratch/signer/master/fips-ipc

# Include any dependencies generated for this target.
include src/lib/CMakeFiles/ip_hashtable.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include src/lib/CMakeFiles/ip_hashtable.dir/compiler_depend.make

# Include the progress variables for this target.
include src/lib/CMakeFiles/ip_hashtable.dir/progress.make

# Include the compile flags for this target's objects.
include src/lib/CMakeFiles/ip_hashtable.dir/flags.make

src/lib/CMakeFiles/ip_hashtable.dir/ip_hashtable.c.o: src/lib/CMakeFiles/ip_hashtable.dir/flags.make
src/lib/CMakeFiles/ip_hashtable.dir/ip_hashtable.c.o: src/lib/ip_hashtable.c
src/lib/CMakeFiles/ip_hashtable.dir/ip_hashtable.c.o: src/lib/CMakeFiles/ip_hashtable.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/scratch/signer/master/fips-ipc/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object src/lib/CMakeFiles/ip_hashtable.dir/ip_hashtable.c.o"
	cd /mnt/scratch/signer/master/fips-ipc/src/lib && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT src/lib/CMakeFiles/ip_hashtable.dir/ip_hashtable.c.o -MF CMakeFiles/ip_hashtable.dir/ip_hashtable.c.o.d -o CMakeFiles/ip_hashtable.dir/ip_hashtable.c.o -c /mnt/scratch/signer/master/fips-ipc/src/lib/ip_hashtable.c

src/lib/CMakeFiles/ip_hashtable.dir/ip_hashtable.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ip_hashtable.dir/ip_hashtable.c.i"
	cd /mnt/scratch/signer/master/fips-ipc/src/lib && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /mnt/scratch/signer/master/fips-ipc/src/lib/ip_hashtable.c > CMakeFiles/ip_hashtable.dir/ip_hashtable.c.i

src/lib/CMakeFiles/ip_hashtable.dir/ip_hashtable.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ip_hashtable.dir/ip_hashtable.c.s"
	cd /mnt/scratch/signer/master/fips-ipc/src/lib && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /mnt/scratch/signer/master/fips-ipc/src/lib/ip_hashtable.c -o CMakeFiles/ip_hashtable.dir/ip_hashtable.c.s

# Object files for target ip_hashtable
ip_hashtable_OBJECTS = \
"CMakeFiles/ip_hashtable.dir/ip_hashtable.c.o"

# External object files for target ip_hashtable
ip_hashtable_EXTERNAL_OBJECTS =

src/lib/libip_hashtable.a: src/lib/CMakeFiles/ip_hashtable.dir/ip_hashtable.c.o
src/lib/libip_hashtable.a: src/lib/CMakeFiles/ip_hashtable.dir/build.make
src/lib/libip_hashtable.a: src/lib/CMakeFiles/ip_hashtable.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/mnt/scratch/signer/master/fips-ipc/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C static library libip_hashtable.a"
	cd /mnt/scratch/signer/master/fips-ipc/src/lib && $(CMAKE_COMMAND) -P CMakeFiles/ip_hashtable.dir/cmake_clean_target.cmake
	cd /mnt/scratch/signer/master/fips-ipc/src/lib && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/ip_hashtable.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/lib/CMakeFiles/ip_hashtable.dir/build: src/lib/libip_hashtable.a
.PHONY : src/lib/CMakeFiles/ip_hashtable.dir/build

src/lib/CMakeFiles/ip_hashtable.dir/clean:
	cd /mnt/scratch/signer/master/fips-ipc/src/lib && $(CMAKE_COMMAND) -P CMakeFiles/ip_hashtable.dir/cmake_clean.cmake
.PHONY : src/lib/CMakeFiles/ip_hashtable.dir/clean

src/lib/CMakeFiles/ip_hashtable.dir/depend:
	cd /mnt/scratch/signer/master/fips-ipc && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /mnt/scratch/signer/master/fips-ipc /mnt/scratch/signer/master/fips-ipc/src/lib /mnt/scratch/signer/master/fips-ipc /mnt/scratch/signer/master/fips-ipc/src/lib /mnt/scratch/signer/master/fips-ipc/src/lib/CMakeFiles/ip_hashtable.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/lib/CMakeFiles/ip_hashtable.dir/depend

