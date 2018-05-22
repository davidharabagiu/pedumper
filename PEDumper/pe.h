#ifndef _PE_H_
#define _PE_H_

#include "map.h"

VOID
DumpPE(
	_In_ PMAP FileMapped,
	_In_ PCWSTR PEFileName,
	_In_ PCWSTR OutputFileName,
	_In_ FILE *LogFile
);
	
#endif // _PE_H_