/*
    @brief  
        Converts an ANSI char string to a hash

    @param[in] LPCSTR String
        The string to hash

    @return
        Hash as DWORD
*/
DWORD HashStringDjb2A(_In_ LPCSTR String)
{
	ULONG Hash = HASH_SEED;
	INT c = 0;

	while (c = *String++)
		Hash = ((Hash << 5) + Hash) + c;

	return Hash;
}

/*
    @brief  
        Converts an ANSI char string to a hash

    @param[in] LPCSTR String
        The string to hash

    @return
        Hash as DWORD
*/
DWORD HashStringDjb2W(_In_ LPCWSTR String)
{
	ULONG Hash = HASH_SEED;
	INT c = 0;

	while (c = *String++)
		Hash = ((Hash << 5) + Hash) + c;

	return Hash;
}