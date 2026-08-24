# --- CRYPTOPP Support ---
set(NS3_WITH_CRYPTOPP "" CACHE PATH "Build with CRYPTOPP support")
set(NS3_CRYPTOPP "OFF" CACHE INTERNAL "ON if CRYPTOPP is found in NS3_WITH_CRYPTOPP")

find_external_library(
  DEPENDENCY_NAME CRYPTOPP
  HEADER_NAME cryptlib.h
  LIBRARY_NAME crypto++ cryptopp
  SEARCH_PATHS /usr/include/cryptopp ${NS3_WITH_CRYPTOPP}
)

if(NOT CRYPTOPP_FOUND)
  message(STATUS "Skipping examples requiring CRYPTOPP")
else()
  include_directories(${CRYPTOPP_INCLUDE_DIRS})
  set(NS3_CRYPTOPP "ON" CACHE INTERNAL "ON if CRYPTOPP is found in NS3_WITH_CRYPTOPP")
endif()

# --- UUID Support ---
set(NS3_WITH_UUID "" CACHE PATH "Build with UUID support")
set(NS3_UUID "OFF" CACHE INTERNAL "ON if UUID is found in NS3_WITH_UUID")

find_external_library(
  DEPENDENCY_NAME uuid
  HEADER_NAME uuid.h
  LIBRARY_NAME uuid
  SEARCH_PATHS /usr/include/uuid ${NS3_WITH_UUID}
)

if(uuid_FOUND)
  include_directories(${uuid_INCLUDE_DIRS})
  link_libraries(${uuid_LIBRARIES})
  set(NS3_UUID "ON" CACHE INTERNAL "ON if UUID is found in NS3_WITH_UUID")
endif()

# --- Common Libraries for Examples ---
set(EXAMPLES_COMMON_LIBS
    ${libinternet}
    ${libqkdnetsim}
    ${libapplications}
    ${libmpi}
    ${libpoint-to-point}
    ${libnetwork}
    ${libcore}
    ${libmobility}
    ${libnetanim}
    ${CRYPTOPP_LIBRARIES}
)

# --- Macro to reduce repetition ---
macro(build_qkd_example name source)
    build_lib_example(
        NAME ${name}
        SOURCE_FILES ${source}
        LIBRARIES_TO_LINK ${EXAMPLES_COMMON_LIBS}
    )
endmacro()

# --- Build Examples ---
build_qkd_example(examples_qkdnetsim_etsi_014 examples_qkdnetsim_etsi_014.cc)
build_qkd_example(examples_qkdnetsim_etsi_004 examples_qkdnetsim_etsi_004.cc)
build_qkd_example(examples_qkdnetsim_etsi_combined_input examples_qkdnetsim_etsi_combined_input.cc)
build_qkd_example(examples_qkdnetsim_secoqc examples_qkdnetsim_secoqc.cc)
build_qkd_example(examples_qkdnetsim_etsi_014_emulation_tap examples_qkdnetsim_etsi_014_emulation_tap.cc)
build_qkd_example(examples_qkdnetsim_etsi_014_emulation examples_qkdnetsim_etsi_014_emulation.cc)
build_qkd_example(examples_qkdnetsim_secoqc_qkd_and_pqc examples_qkdnetsim_secoqc_qkd_and_pqc.cc)
