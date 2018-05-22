#ifndef _MAP_H_
#define _MAP_H_

#include <Windows.h>
#include <Shlwapi.h>
#include <stdio.h>

#define STATUS_SUCCESS 0
#define STATUS_FILE_HANDLING_ERROR -1


typedef struct _MAP
{
	HANDLE hFile;
	HANDLE hMap;
	BYTE * buffer;
	DWORD fileSize;
}MAP, *PMAP;

INT 
MapFile(PWSTR FileName,
	DWORD AccessRights,
	PMAP Map
);

VOID
UnMapFile(
    PMAP Map
);


#endif // !_MAP_H_

