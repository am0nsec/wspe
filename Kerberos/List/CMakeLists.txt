# @file        CMakeLists.txt
# @author      Paul L. (@am0nsec)
# @version     1.0
# @brief       Kerberos list tickets.
# @details     
# @link        https://github.com/am0nsec/wspe
# @copyright   This project has been released under the GNU Public License v3 license.

add_executable(pklist
	"src/main.c"
)

set_property(TARGET pklist
	PROPERTY
	MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Rlease>:Rlease>"
)