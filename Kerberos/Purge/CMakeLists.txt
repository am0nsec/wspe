# @file        CMakeLists.txt
# @author      Paul L. (@am0nsec)
# @version     1.0
# @brief       Kerberos purge tickets.
# @details     
# @link        https://github.com/am0nsec/wspe
# @copyright   This project has been released under the GNU Public License v3 license.

add_executable(pkpurge
	"src/main.c"
)

set_property(TARGET pkpurge
	PROPERTY
	MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Rlease>:Rlease>"
)