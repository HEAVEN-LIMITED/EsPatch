#pragma once

#define memset MemSet
#define memcpy MemCpy

void MemCpy(UCHAR *dst, UCHAR *src, int len);
void MemSet(UCHAR *dst, UCHAR v, int len);
