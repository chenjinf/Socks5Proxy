// stdafx.h : ��׼ϵͳ�����ļ��İ����ļ���
// ���Ǿ���ʹ�õ��������ĵ�
// �ض�����Ŀ�İ����ļ�
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>



// TODO:  �ڴ˴����ó�����Ҫ������ͷ�ļ�
#define WIN32_LEAN_AND_MEAN             //  �� Windows ͷ�ļ����ų�����ʹ�õ���Ϣ
#include <WinSock2.h>
#include <windows.h>
#include <ws2ipdef.h>
#include <IPHlpApi.h>
#include <boost/asio.hpp>
#include <boost/bind/bind.hpp>
#include <iostream>
#include <vector>
#include <memory>
#include <iomanip>
#include <thread>
#include <unordered_map>
#include <mutex>
#include <queue>

namespace asio = boost::asio;
using asio::ip::tcp;
using namespace std;