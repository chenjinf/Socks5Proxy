#pragma once
#define LOGGING_TO_FILE 0
//#define LOGGING_USING_STDIO
//#define LOGGING_USING_DBGMSG
#if LOGGING_TO_FILE
#include "util/Logger.h"
#define DKTRACEA LOG_INFO
#define DKERRORA LOG_ERROR
#define DKTRACEW LOG_INFOW
#define DKERROREW LOG_ERRORW
#else
#ifdef LOGGING_USING_STDIO
// 信息输出到“标准输出”
#define DKTRACEA printf
#define DKERRORA printf
#define DKTRACEW wprintf
#define DKERROREW wprintf
#else
#ifdef LOGGING_USING_DBGMSG
// 信息输出到“Windows debug message”
#include "util/DebugMessage.h"
#define DKTRACEA DebugMessageA
#define DKERRORA DebugMessageA
#define DKTRACEW DebugMessageW
#define DKERRORW DebugMessageW
#else
#define DKTRACEA 
#define DKERRORA 
#define DKTRACEW 
#define DKERRORW 
#endif
#endif //LOGGING_USING_STDIO
#endif