# @file        CMakeLists.txt
# @data        10/03/2021
# @author      Paul L. (@am0nsec)
# @version     1.0
# @brief       Office Outlook CMake configuration file.
# @details     
# @link        https://github.com/am0nsec/wspe
# @copyright   This project has been released under the GNU Public License v3 license.

include_directories(inc)
add_executable(outlook_util
	"src/main.c"
	"src/outlook.c"
)