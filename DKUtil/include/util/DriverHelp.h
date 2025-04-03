/**
* \copyright (C)2016 万兆天空
* \file DriverHelp.h 
* \brief DriverHelp.h 定义 CDriverHelp 类，CDriverHelp封装对驱动服务的一些操作。
* \version v1.0
* \author Run
* \date 2015.03.06
*/

#pragma once
#include <windows.h>

/**
 * @defgroup DRIVER_OPEATION 驱动操作
 * \brief 定义驱动的操作接口
 * @{
 */

/**
 * \brief CDriverHelp封装对驱动服务的一些操作。
 *
 * 包括以下功能：
 * - 加载驱动
 * - 卸载指定名称的驱动服务
 * - 打开驱动通信
 * - 关闭驱动通信
 * - 向驱动层发送数据
 * 
 */
class CDriverHelp
{
public:
	CDriverHelp(void);
	~CDriverHelp(void);


	/**
	 * \brief 功  能:加载指定驱动
	 * \param DriverAbsPath 驱动程序绝对路径
	 * \param ServiceName 服务名
	 * \param DisplayName 服务显示名
	 * \return 成功:0;失败:返回GetLastError错误码
	 */
	DWORD DrvLoadDriver(const CHAR* v_szDriverAbsPath, 
		              const CHAR* v_szServiceName, 
		              const CHAR* v_szDisplayName);

	/**
	 * \brief 功  能:卸载指定名称的驱动服务
	 * \param ServiceName 服务的名称
	 * \return 成功:0;失败:返回GetLastError错误码,对不存在的服务返回-1(成功)
	*/
	DWORD DrvUnloadDriver(const CHAR* v_szServiceName);

	/**
	 * \brief 功  能:打开驱动通信
	 * \param v_szDeviceName 设备名称
	 * \return 成功:TRUE; 失败:FALSE
	*/
	BOOL DrvOpenDriver(const CHAR* v_szDeviceName);

	/**
	 * \brief 功  能:关闭驱动通信
	 * \return 成功:TRUE; 失败:FALSE
	 */
	BOOL DrvCloseDriver();

	/**
	 * \brief 功  能:向驱动层发送数据
	 * \param v_nCtrlCode  驱动控制命令
	 * \param v_szData     发送到驱动的数据
	 * \param v_iDataLen   发送数据长度
	 * \param v_szResult   驱动返回结果
	 * \param v_iResultLen 驱动返回结果长度
	 * \return 成功:TRUE; 失败:FALSE
	*/
	BOOL DrvSendCommand(const DWORD v_nCtrlCode, 
		const char*    v_szData, 
		const DWORD    v_iDataLen, 
		char*          v_szResult, 
		DWORD&         v_iResultLen);


protected:

private:

	SC_HANDLE m_hScManager;  //服务控制管理器句柄
	long      m_nRefcount;
	HANDLE    m_hDevice;     //设备句柄

	//打开服务管理器
	DWORD DrvOpenScManager(int open);
	//创建服务
	DWORD DrvCreateService(const CHAR* v_szDriverAbsolutePath, 
		const CHAR* ServiceName,const CHAR* ServiceDispalyName,SC_HANDLE* phService);
    //添加服务
	DWORD DrvAddService(const CHAR* DriverAbsPath, const CHAR* ServiceName, 
		const CHAR* DisplayName);
	//删除服务
	DWORD DrvDeleteService(const CHAR* ServiceName);


};

/** @} */