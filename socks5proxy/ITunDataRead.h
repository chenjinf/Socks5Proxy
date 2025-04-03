#pragma once
class ITunDataRead
{
public:
	virtual void OnReadTun(BYTE *buf, int len) = 0;
protected:
private:
};