#include <stdlib.h>
#include "pe.h"

#define MAX_PATH 1024

VOID
ConvWideStr(
    PWSTR Dest,
    PSTR Src
);

INT
Dump(
    PCWSTR FileName,
    FILE *LogFile
);

INT
DumpDir(
	PCWSTR DirName,
	FILE *LogFile
);

INT
main(
    INT argc,
    PCHAR *argv
)
{
	INT status;

	if (argc < 2)
	{
		printf("Usage : %s <path> \n", argv[0]);
		return STATUS_INVALID_PARAMETER;
	}

	FILE *logFile;
	errno_t errOpen = fopen_s(&logFile, "log.txt", "w");
	if (errOpen != 0)
	{
		printf("Error while opening log.txt: 0x%08X\n", errOpen);
		return -1;
	}
	
    if (PathIsDirectoryA(argv[1]))
    {
        WCHAR dirName[MAX_PATH];
        ConvWideStr(dirName, argv[1]);
        DumpDir(dirName, logFile);
    }
    else if (PathFileExistsA(argv[1]))
    {
        WCHAR fileName[MAX_PATH];
        ConvWideStr(fileName, argv[1]);

        if (Dump(fileName, logFile) < 0)
        {
            fprintf(logFile, "Cannot map file %ws.\n", fileName);
            return STATUS_INVALID_PARAMETER;
        }
    }
    else
    {
        fprintf(logFile, "Invalid path: %s\n", argv[1]);
        return STATUS_INVALID_PARAMETER;
    }

	fclose(logFile);

	return 0;
}

VOID ConvWideStr(
    PWSTR dest,
    PSTR src
)
{
    for (; *dest = *src; ++src, ++dest)
        ;
}

INT
Dump(
    PCWSTR FileName,
    FILE *LogFile
)
{
    MAP map;

    WCHAR outputFile[MAX_PATH];
    wcscpy_s(outputFile, MAX_PATH, FileName);
    wcscat_s(outputFile, MAX_PATH, L" dump.txt");
    //PathStripPathW(outputFile);

	PWCHAR occurrence;
	while ((occurrence = wcsrchr(outputFile, L'\\')) != NULL)
	{
		*occurrence = L'-';
	}

    INT status = MapFile(FileName, GENERIC_READ, &map);
    if (status >= 0)
    {
        DumpPE(&map, FileName, outputFile, LogFile);
    }

    UnMapFile(&map);

    return status;
}

INT
DumpDir(
    PCWSTR DirName,
    FILE *LogFile
)
{
    WCHAR fileName[MAX_PATH];
    WCHAR dirSearch[MAX_PATH];
    
    PathCombineW(dirSearch, DirName, L"*");
    WIN32_FIND_DATAW findData;
    HANDLE hSearch = FindFirstFileW(dirSearch, &findData);

    if (hSearch == INVALID_HANDLE_VALUE)
    {
        printf("Error while calling FindFirstFile: 0x%08X\n", GetLastError());
        return -1;
    }

    do
    {
        if (!wcscmp(findData.cFileName, L".") || !wcscmp(findData.cFileName, L".."))
        {
            continue;
        }
        PathCombineW(fileName, DirName, findData.cFileName);
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            DumpDir(fileName, LogFile);
            continue;
        }
        if (Dump(fileName, LogFile) < 0)
        {
            printf("Cannot map file\n");
            FindClose(hSearch);
            return -1;
        }
    } while (FindNextFileW(hSearch, &findData));

    FindClose(hSearch);
}