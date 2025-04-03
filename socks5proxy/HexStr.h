#pragma once

bool StrToBcd(const char *sz, int nSzLen, void *buf, int len);
std::string BcdToStr(const void *buf, int len);
std::string BcdToStrFmt(const void* buf, int len);
bool BcdToStr(const void *buf, int len, char *sz, int szLen);