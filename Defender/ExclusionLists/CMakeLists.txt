# @file        CMakeLists.txt
# @author      Paul L. (@am0nsec)
# @version     1.0
# @brief       List Windows Defender Exclusion Lists
# @details     
# @link        https://github.com/am0nsec/wspe
# @copyright   This project has been released under the GNU Public License v3 license.

include_directories(inc)

add_executable(defender-exclusion-list
	"main.c"
	"src/defender.c"
 )