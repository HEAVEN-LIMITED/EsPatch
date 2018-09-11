
void MemCpy(unsigned char *dst, unsigned char *src, int len) {
	while (len--)
		dst[len] = src[len];
}

void MemSet(unsigned char *dst, unsigned char v, int len) {
	while (len--)
		dst[len] = v;
}
