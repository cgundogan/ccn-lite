cmake_minimum_required(VERSION 2.8)
project(ccnl-pkt)
 
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

include_directories(include ../ccnl-core/include ../ccnl-fwd/include)

set(SOURCES
  "src/ccnl-pkt-builder.c"
  "src/ccnl-pkt-switch.c"
)
if (CCNL_PACKETFORMAT_NDN)
  if (CCNL_PACKETFORMAT_NDNV03)
    set(SOURCES "${SOURCES}" "src/ndnv03/buffer.c")
    set(SOURCES "${SOURCES}" "src/ndnv03/name.c")
    set(SOURCES "${SOURCES}" "src/ndnv03/tlv.c")
    set(SOURCES "${SOURCES}" "src/ndnv03/data.c")
    set(SOURCES "${SOURCES}" "src/ndnv03/interest.c")
    include_directories(include/ndnv03)
  else ()
    set(SOURCES "${SOURCES}" "src/ccnl-pkt-ndntlv.c")
  endif()
endif ()
if (CCNL_PACKETFORMAT_CCNTLV)
  set(SOURCES "${SOURCES}" "src/ccnl-pkt-ccntlv.c")
endif ()
if (CCNL_PACKETFORMAT_CCNB)
  set(SOURCES "${SOURCES}" "src/ccnl-pkt-ccnb.c")
endif ()
if (CCNL_PACKETFORMAT_LOCALRPC)
  set(SOURCES "${SOURCES}" "src/ccnl-pkt-localrpc.c")
endif ()

add_library(${PROJECT_NAME} STATIC ${SOURCES})
