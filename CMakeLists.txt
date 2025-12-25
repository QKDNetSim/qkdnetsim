# ---- Crypto++ ----
set(NS3_WITH_CRYPTOPP "" CACHE PATH "Build with CRYPTOPP support")

find_external_library(
  DEPENDENCY_NAME CRYPTOPP
  HEADER_NAME cryptlib.h
  LIBRARY_NAME crypto++ cryptopp
  SEARCH_PATHS /usr/include/cryptopp ${NS3_WITH_CRYPTOPP}
)

if(NOT CRYPTOPP_FOUND)
  message(STATUS "qkdnetsim disabled: Crypto++ not found")
  return()
endif()

include_directories(${CRYPTOPP_INCLUDE_DIRS})

# ---- UUID ----
find_external_library(
  DEPENDENCY_NAME uuid
  HEADER_NAME uuid.h
  LIBRARY_NAME uuid
  SEARCH_PATHS /usr/include/uuid
)

if(uuid_FOUND)
  include_directories(${uuid_INCLUDE_DIRS})
endif()

# ---- qkdnetsim internal includes ----
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/model
  ${CMAKE_CURRENT_SOURCE_DIR}/helper
  ${CMAKE_CURRENT_SOURCE_DIR}/utils
)

# ---- qkdnetsim module ----
build_lib(
  LIBNAME qkdnetsim

  SOURCE_FILES
    model/q-buffer.cc
    model/s-buffer.cc
    model/qkd-control.cc
    model/qcen-control.cc
    model/qkd-graph.cc
    model/qkd-total-graph.cc
    model/qkd-graph-manager.cc
    model/qkd-key.cc
    model/app-key.cc
    model/app-key-stream.cc
    model/qkd-encryptor.cc
    model/qkd-location-register.cc
    model/qkd-location-register-entry.cc
    model/qkd-postprocessing-application.cc
    model/qkd-key-manager-system-application.cc
    model/qkd-kms-queue-logic.cc
    model/qkd-app-004.cc
    model/qkd-app-014.cc
    model/qkd-app-header.cc
    helper/qkd-app-helper.cc
    helper/qkd-link-helper.cc 
    utils/uuid.cc

  HEADER_FILES
    model/q-buffer.h
    model/s-buffer.h
    model/qkd-control.h
    model/qcen-control.h
    model/qkd-graph.h
    model/qkd-total-graph.h
    model/qkd-graph-manager.h
    model/qkd-key.h
    model/app-key.h
    model/app-key-stream.h
    model/qkd-encryptor.h
    model/qkd-location-register.h
    model/qkd-location-register-entry.h
    model/qkd-postprocessing-application.h
    model/qkd-key-manager-system-application.h
    model/qkd-kms-queue-logic.h
    model/qkd-app-004.h
    model/qkd-app-014.h
    model/qkd-app-header.h
    helper/qkd-app-helper.h
    helper/qkd-link-helper.h 
    utils/uuid.h
    utils/http.h
    utils/json.h

  LIBRARIES_TO_LINK
    ${libcore}
    ${libnetwork}
    ${libinternet}
    ${libapplications}
    ${libstats}
    ${CRYPTOPP_LIBRARIES}
    ${uuid_LIBRARIES}
)
