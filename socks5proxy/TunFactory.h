#pragma once

class IXyzTun;

class CTunFactory
{
public:
	CTunFactory(){;}
	~CTunFactory(){;}
public:
	static IXyzTun* CreateTun();
	static void DestoryTun(IXyzTun* pTun);
};