# @file        CMakeLists.txt
# @author      Paul L. (@am0nsec)
# @version     1.0
# @brief       Kerberos request kerberos TGT.
# @details     
# @link        https://github.com/am0nsec/wspe
# @copyright   This project has been released under the GNU Public License v3 license.

add_executable(pkasktgt
	"main.c"
	"kerberos.c"
	"socket.c"

	"kerberos.h"
	"socket.h"
)

set_property(TARGET pkasktgt
	PROPERTY
	MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Rlease>:Rlease>"
)