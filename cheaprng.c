ULONG rol32(ULONG d, UCHAR v)
{
	return (d << v) | (d >> (32 - v));
}
ULONG ror32(ULONG d, UCHAR v)
{
	return (d >> v) | (d << (32 - v));
}

ULONG seed;
UCHAR getRandomByte()
{
	result = seed & 0xFFFFFFFF;
	result = ror32(result, 3) | rol32(result, 5);
	result = result * (ror32(result, 12));
	result = result * 0x16645186;
	result = rol32(result, result & 0x1F);
	result = (result & 0xFFFF) + ((result >> 16) & 0xFFFF);
	return (result & 0xFF) ^ ((result >> 8) & 0xFF);
}

ULONG getRandomDword() {
	return (getbyte() << 24) | (getbyte() << 16) | (getbyte() << 8) | getbyte();
}

UCHAR __inline biteFlippe(UCHAR candidate) {
	return candidate ^ (1 << (getRandomByte() & 0b111));
}

// 1 percent byte modification => rate = 100
void bufferFlip(PUCHAR buff, ULONG size, UCHAR rate) {
	ULONG i = 0, offst = 0, msk = 0, tmp;
    
	msk = 0;
	i = 0;
	while (size > i) {
		i++;
		msk = (msk << 1) | 1;
	}
	if (msk > size * 2 - size / 2)
		msk = msk >> 1;
	i = 0;

	while (i < size / rate) {
		tmp = 0xFFFFFFFF;
		while (tmp > size)
			tmp = getRandomDword() & msk;
		buff[tmp] = biteFlippe(buff[tmp]);
		i++;
	}

}

void initPrng() {
    seed = __rdtsc() & 0xFFFFFFFF;
}
