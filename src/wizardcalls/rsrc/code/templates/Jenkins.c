DWORD HashStringJenkinsOneAtATimeA(_In_ LPCSTR String)
{
	SIZE_T Index = 0;
	DWORD Hash = HASH_SEED;
    SIZE_T Length = 0;
    LPCSTR String2;
    
    for (String2 = String; *String2; ++String2);
	Length = (String2 - String)

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << 10;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}

DWORD HashStringJenkinsOneAtATimeW(_In_ LPCWSTR String)
{
	SIZE_T Index = 0;
	DWORD Hash = HASH_SEED;
    SIZE_T Length = 0;
    LPCWSTR String2;
    
    for (String2 = String; *String2; ++String2);
	Length = (String2 - String)

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << 10;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}