#include "stdafx.h"
#include "TunFactory.h"
#include "GlobalTun.h"
#include <string>



IXyzTun* CTunFactory::CreateTun()
{
	CGlobalTun* pTun = new CGlobalTun;
	return pTun;
}

void CTunFactory::DestoryTun(IXyzTun* pTun)
{
	if (pTun)
	{
		delete pTun;
	}
}

