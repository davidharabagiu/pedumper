#include "map.h"

VOID
UnMapFile(
    PMAP Map
)
{
	if (Map == NULL)
	{
		printf("Invalid parameter(s) %s %d \n", __FILE__, __LINE__);
		return;
	}

	if (Map->buffer != NULL)
	{
		UnmapViewOfFile(Map->buffer);
		Map->buffer = NULL;
	}

	if (Map->hMap != NULL)
	{
		CloseHandle(Map->hMap);
		Map->hMap = NULL;
	}

	if (Map->hFile != NULL)
	{
		CloseHandle(Map->hFile);
		Map->hFile = INVALID_HANDLE_VALUE;
	}

	Map->fileSize = 0;
}

INT
MapFile(
    PWSTR FileName,
	DWORD AccessRights,
	PMAP Map
)
{
	DWORD extraFileSize;
	INT status;
	DWORD access;

	status = STATUS_SUCCESS;
	access = 0;

	if (FileName == NULL ||
		Map == NULL)
	{
		printf("Invalid parameter(s) \n");
		return STATUS_INVALID_PARAMETER; 
	}

	// Initializam variabila de iesire
	Map->buffer = NULL;
	Map->fileSize = 0;
	Map->hFile = INVALID_HANDLE_VALUE;
	Map->hMap = NULL;

	// Apelam CreateFileW
	Map->hFile = CreateFileW(FileName,
		AccessRights,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
    );
	if (INVALID_HANDLE_VALUE == Map->hFile)
	{
		printf("CreateFile Failed : %d \n", GetLastError());
		return STATUS_FILE_HANDLING_ERROR;
	}

	//Verificam Size
	Map->fileSize = GetFileSize(Map->hFile, &extraFileSize);
	if (extraFileSize > 0)
	{
		printf("Overflow file size\n");
		status = STATUS_FILE_HANDLING_ERROR;
		goto cleanup;
	}
	if (Map->fileSize == 0) // Minimal file size
	{
		printf("Size is too low\n");
		status = STATUS_FILE_HANDLING_ERROR;
		goto cleanup;
	}

	// Calculam AccessRights pentru CreateFileMapping
	if (AccessRights & GENERIC_WRITE)
	{
		access = PAGE_READWRITE;
	}
	else
	{
		access = PAGE_READONLY;
	}
	
	// Apelam CreateFileMapping
	Map->hMap = CreateFileMapping(Map->hFile,
		NULL,
		access,
		0,
		0,
		NULL);
	if (NULL == Map->hMap)
	{
		printf("CreateFileMapping failed %d \n", GetLastError());
		status = STATUS_FILE_HANDLING_ERROR;
		goto cleanup;
	}
	
	// Calculam AccessRights pentru MapViewOfFile
	if (AccessRights & GENERIC_WRITE)
	{
		access = FILE_MAP_READ | FILE_MAP_WRITE;
	}
	else
	{
		access = FILE_MAP_READ;
	}

	// Apelam MapViewOfFile
	Map->buffer = MapViewOfFile(Map->hMap,
		access,
		0,
		0,
		0); 
	if (NULL == Map->buffer)
	{
		printf("MapViewOfFile failed %d \n", GetLastError());
		status = STATUS_FILE_HANDLING_ERROR;
		goto cleanup;
	}

cleanup:
	if (status < 0)
	{
		UnMapFile(Map);
	}
	return status;
}