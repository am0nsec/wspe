# @file        CMakeLists.txt
# @data        13/06/2022
# @author      Paul L. (@am0nsec)
# @version     1.0
# @brief       Microsoft Debug Interface Access (DIA) CMake configuration file.
# @details     
# @link        https://github.com/am0nsec/wspe
# @copyright   This project has been released under the GNU Public License v3 license.

include_directories(inc)

add_executable(dia-dump
	"src/main.c"
	"src/callback.c"
	"src/interface.c"
	"src/dirutil.c"
)

# Add all post-build commands
add_custom_command(
	TARGET dia-dump
	POST_BUILD
	COMMAND ${CMAKE_COMMAND} -E echo "Start post-build commands" 

	# Make all the directories
	COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/DIA/pdb"
	COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/DIA/msdia"
	
	# Copy binaries required
	COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_SOURCE_DIR}/DIA/tools/symsrv.dll" "${CMAKE_BINARY_DIR}/DIA/pdb/"
	COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_SOURCE_DIR}/DIA/tools/msdia140.dll" "${CMAKE_BINARY_DIR}/DIA/msdia/"

	# End
	COMMAND ${CMAKE_COMMAND} -E echo "Start post-build commands ... OK" 
)
