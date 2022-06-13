# @file        CMakeLists.txt
# @data        12/02/2021
# @author      Paul L. (@am0nsec)
# @version     1.0
# @brief       WSPE CMake configuration file.
cmake_minimum_required(VERSION 3.16)

# You kids get off my lawn!
if (NOT ${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
	message(FATAL_ERROR "You kids get off my lawn with Linux ...")
endif()


# Dummy project
project(wspe VERSION 1.0 LANGUAGES C)

# Kerberos
add_subdirectory(Kerberos/List)
add_subdirectory(Kerberos/Purge)
add_subdirectory(Kerberos/GetTicket)
add_subdirectory(Kerberos/AskTGT)

# Office
add_subdirectory(Office/outlook)

# Windows Defender
add_subdirectory(Defender/ExclusionLists)

# Microsoft Debug Interface Access (DIA)
add_subdirectory(DIA)
