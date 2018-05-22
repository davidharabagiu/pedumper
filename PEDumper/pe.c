#include "pe.h"

PBYTE
VaToPa(
    _In_ PIMAGE_DOS_HEADER Idh,
    _In_ PIMAGE_NT_HEADERS Inh,
    _In_ ULONGLONG VirtualAddress
)
{
    PIMAGE_SECTION_HEADER ish = (PIMAGE_SECTION_HEADER)((PBYTE)&Inh->OptionalHeader + Inh->FileHeader.SizeOfOptionalHeader);
    while (!(VirtualAddress >= ish->VirtualAddress && VirtualAddress < ish->VirtualAddress + ish->SizeOfRawData))
        ++ish;
    return (PBYTE)Idh + ish->PointerToRawData + VirtualAddress - ish->VirtualAddress;
}

VOID
DumpIdh(
    _In_ PIMAGE_DOS_HEADER Idh,
    _In_ FILE *OutputFile
)
{
    fprintf(OutputFile, "Printing from DOS Header:...\n");
    fprintf(OutputFile, "\te_lfanew: 0x%08hX\n", Idh->e_lfanew);
}

VOID
DumpIfh(
    _In_ PIMAGE_NT_HEADERS Inh,
    _In_ FILE *OutputFile
)
{
    fprintf(OutputFile, "\nPrinting from IMAGE_FILE_HEADER:\n");
    fprintf(OutputFile, "\tMachine: 0x%04hX\n", Inh->FileHeader.Machine);
    fprintf(OutputFile, "\tNumber of sections: 0x%04hX\n", Inh->FileHeader.NumberOfSections);
    fprintf(OutputFile, "\tSize of optional header: 0x%04hX\n", Inh->FileHeader.SizeOfOptionalHeader);
}

VOID
DumpIoh32(
    _In_ PIMAGE_NT_HEADERS32 Inh,
    _In_ FILE *OutputFile
)
{
    fprintf(OutputFile, "\nPrinting from IMAGE_OPTIONAL_HEADER:\n");
    fprintf(OutputFile, "\tMagic: 0x%04hX\n", Inh->OptionalHeader.Magic);
    fprintf(OutputFile, "\tAddress of entry point: 0x%08X\n", Inh->OptionalHeader.AddressOfEntryPoint);
    fprintf(OutputFile, "\tImage base: 0x%08X\n", Inh->OptionalHeader.ImageBase);
    fprintf(OutputFile, "\tSection alignment: 0x%08X\n", Inh->OptionalHeader.SectionAlignment);
    fprintf(OutputFile, "\tFile alignment: 0x%08X\n", Inh->OptionalHeader.FileAlignment);
    fprintf(OutputFile, "\tSize of image: 0x%08X\n", Inh->OptionalHeader.SizeOfImage);
    fprintf(OutputFile, "\tSubsystem: 0x%04hX\n", Inh->OptionalHeader.Subsystem);
    fprintf(OutputFile, "\tDll Characteristics: 0x%04hX\n", Inh->OptionalHeader.DllCharacteristics);
    fprintf(OutputFile, "\tSize of stack reserve: 0x%08X\n", Inh->OptionalHeader.SizeOfStackReserve);
    fprintf(OutputFile, "\tSize of stack commit: 0x%08X\n", Inh->OptionalHeader.SizeOfStackCommit);
    fprintf(OutputFile, "\tSize of heap reserve: 0x%08X\n", Inh->OptionalHeader.SizeOfHeapReserve);
    fprintf(OutputFile, "\tSize of heap commit: 0x%08X\n", Inh->OptionalHeader.SizeOfHeapCommit);
    fprintf(OutputFile, "\tNumber of rva and sizes: 0x%08X\n", Inh->OptionalHeader.NumberOfRvaAndSizes);
    fprintf(OutputFile, "\nPrinting from IMAGE_DIRECTORY_ENTRY_EXPORT:\n");
    fprintf(OutputFile, "\tVirtual address: 0x%08X\n", Inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    fprintf(OutputFile, "\tSize: 0x%08X\n", Inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);
    fprintf(OutputFile, "\nPrinting from IMAGE_DIRECTORY_ENTRY_IMPORT:\n");
    fprintf(OutputFile, "\tVirtual address: 0x%08X\n", Inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    fprintf(OutputFile, "\tSize: 0x%08X\n", Inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
    fprintf(OutputFile, "\nPrinting from IMAGE_DIRECTORY_ENTRY_RESOURCE:\n");
    fprintf(OutputFile, "\tVirtual address: 0x%08X\n", Inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
    fprintf(OutputFile, "\tSize: 0x%08X\n", Inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size);
    fprintf(OutputFile, "\nPrinting from IMAGE_DIRECTORY_ENTRY_IAT:\n");
    fprintf(OutputFile, "\tVirtual address: 0x%08X\n", Inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);
    fprintf(OutputFile, "\tSize: 0x%08X\n", Inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);
}

VOID
DumpIoh64(
    _In_ PIMAGE_NT_HEADERS64 Inh,
	_In_ FILE *OutputFile
)
{
    fprintf(OutputFile, "\nPrinting from IMAGE_OPTIONAL_HEADER:\n");
    fprintf(OutputFile, "\tMagic: 0x%04hX\n", Inh->OptionalHeader.Magic);
    fprintf(OutputFile, "\tAddress of entry point: 0x%08X\n", Inh->OptionalHeader.AddressOfEntryPoint);
    fprintf(OutputFile, "\tImage base: 0x%016llX\n", Inh->OptionalHeader.ImageBase);
    fprintf(OutputFile, "\tSection alignment: 0x%08X\n", Inh->OptionalHeader.SectionAlignment);
    fprintf(OutputFile, "\tFile alignment: 0x%08X\n", Inh->OptionalHeader.FileAlignment);
    fprintf(OutputFile, "\tSize of image: 0x%08X\n", Inh->OptionalHeader.SizeOfImage);
    fprintf(OutputFile, "\tSubsystem: 0x%04hX\n", Inh->OptionalHeader.Subsystem);
    fprintf(OutputFile, "\tDll Characteristics: 0x%04hX\n", Inh->OptionalHeader.DllCharacteristics);
    fprintf(OutputFile, "\tSize of stack reserve: 0x%016llX\n", Inh->OptionalHeader.SizeOfStackReserve);
    fprintf(OutputFile, "\tSize of stack commit: 0x%016llX\n", Inh->OptionalHeader.SizeOfStackCommit);
    fprintf(OutputFile, "\tSize of heap reserve: 0x%016llX\n", Inh->OptionalHeader.SizeOfHeapReserve);
    fprintf(OutputFile, "\tSize of heap commit: 0x%016llX\n", Inh->OptionalHeader.SizeOfHeapCommit);
    fprintf(OutputFile, "\tNumber of rva and sizes: 0x%08X\n", Inh->OptionalHeader.NumberOfRvaAndSizes);
    fprintf(OutputFile, "\nPrinting from IMAGE_DIRECTORY_ENTRY_EXPORT:\n");
    fprintf(OutputFile, "\tVirtual address: 0x%08X\n", Inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    fprintf(OutputFile, "\tSize: 0x%08X\n", Inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);
    fprintf(OutputFile, "\nPrinting from IMAGE_DIRECTORY_ENTRY_IMPORT:\n");
    fprintf(OutputFile, "\tVirtual address: 0x%08X\n", Inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    fprintf(OutputFile, "\tSize: 0x%08X\n", Inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
    fprintf(OutputFile, "\nPrinting from IMAGE_DIRECTORY_ENTRY_RESOURCE:\n");
    fprintf(OutputFile, "\tVirtual address: 0x%08X\n", Inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
    fprintf(OutputFile, "\tSize: 0x%08X\n", Inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size);
    fprintf(OutputFile, "\nPrinting from IMAGE_DIRECTORY_ENTRY_IAT:\n");
    fprintf(OutputFile, "\tVirtual address: 0x%08X\n", Inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);
    fprintf(OutputFile, "\tSize: 0x%08X\n", Inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);
}

VOID
DumpIsh(
    _In_ PIMAGE_SECTION_HEADER Ish,
	_In_ FILE *OutputFile
)
{
    CHAR sectionName[9];
    strncpy_s(sectionName, 9, Ish->Name, 8);
    sectionName[8] = '\0';

    fprintf(OutputFile, "\nPrinting from IMAGE_SECTION_HEADER:\n");
    fprintf(OutputFile, "\tName: %s\n", sectionName);
    fprintf(OutputFile, "\tMisc: 0x%08X\n", Ish->Misc.PhysicalAddress);
    fprintf(OutputFile, "\tVirtual address: 0x%08X\n", Ish->VirtualAddress);
    fprintf(OutputFile, "\tSize of raw data: 0x%08X\n", Ish->SizeOfRawData);
    fprintf(OutputFile, "\tCharacteristics: 0x%08X\n", Ish->Characteristics);
}

VOID
DumpIed32(
    _In_ PIMAGE_DOS_HEADER Idh,
    _In_ PIMAGE_NT_HEADERS32 Inh32,
    _In_ PIMAGE_EXPORT_DIRECTORY Ied,
	_In_ FILE *OutputFile
)
{
    PIMAGE_NT_HEADERS inh = (PIMAGE_NT_HEADERS)Inh32;

    fprintf(OutputFile, "\nPrinting from IMAGE_EXPORT_DIRECTORY:\n");
    fprintf(OutputFile, "\tName: 0x%08X (%s)\n", Ied->Name, (PCHAR)VaToPa(Idh, inh, Ied->Name));
    fprintf(OutputFile, "\tBase: 0x%08X\n", Ied->Base);
    fprintf(OutputFile, "\tNumber of functions: 0x%08X\n", Ied->NumberOfFunctions);
    fprintf(OutputFile, "\tNumber of names: 0x%08X\n", Ied->NumberOfNames);
    fprintf(OutputFile, "\tAddress of functions: 0x%08X\n", Ied->AddressOfFunctions);
    fprintf(OutputFile, "\tAddress of names: 0x%08X\n", Ied->AddressOfNames);
    fprintf(OutputFile, "\tAddress of name ordinals: 0x%08X\n", Ied->AddressOfNameOrdinals);

    PWORD name_ordinals = (PWORD)VaToPa(Idh, inh, Ied->AddressOfNameOrdinals);
    PDWORD names = (PDWORD)VaToPa(Idh, inh, Ied->AddressOfNames);
    PDWORD functions = (PDWORD)VaToPa(Idh, inh, Ied->AddressOfFunctions);

    fprintf(OutputFile, "\n\t%-6s %-10s %s\n", "NO", "Address", "Name");
    for (DWORD i = 0; i < Ied->NumberOfNames; ++i)
    {
        fprintf(
			OutputFile,
			"\t0x%04hX 0x%08X %s\n",
			name_ordinals[i],
			functions[name_ordinals[i]],
			(PCHAR)VaToPa(Idh, inh, names[i])
		);
    }
}

VOID
DumpIed64(
    _In_ PIMAGE_DOS_HEADER Idh,
    _In_ PIMAGE_NT_HEADERS64 Inh64,
    _In_ PIMAGE_EXPORT_DIRECTORY Ied,
	_In_ FILE *OutputFile
)
{
    PIMAGE_NT_HEADERS inh = (PIMAGE_NT_HEADERS)Inh64;

    fprintf(OutputFile, "\nPrinting from IMAGE_EXPORT_DIRECTORY:\n");
    fprintf(OutputFile, "\tName: 0x%08X (%s)\n", Ied->Name, (PCHAR)VaToPa(Idh, inh, Ied->Name));
    fprintf(OutputFile, "\tBase: 0x%08X\n", Ied->Base);
    fprintf(OutputFile, "\tNumber of functions: 0x%08X\n", Ied->NumberOfFunctions);
    fprintf(OutputFile, "\tNumber of names: 0x%08X\n", Ied->NumberOfNames);
    fprintf(OutputFile, "\tAddress of functions: 0x%08X\n", Ied->AddressOfFunctions);
    fprintf(OutputFile, "\tAddress of names: 0x%08X\n", Ied->AddressOfNames);
    fprintf(OutputFile, "\tAddress of name ordinals: 0x%08X\n", Ied->AddressOfNameOrdinals);

    PWORD name_ordinals = (PWORD)VaToPa(Idh, inh, Ied->AddressOfNameOrdinals);
    PDWORD names = (PDWORD)VaToPa(Idh, inh, Ied->AddressOfNames);
    PDWORD functions = (PDWORD)VaToPa(Idh, inh, Ied->AddressOfFunctions);

    fprintf(OutputFile, "\n\t%-6s %-10s %s\n", "NO", "Address", "Name");
    for (DWORD i = 0; i < Ied->NumberOfNames; ++i)
    {
        fprintf(
			OutputFile,
            "\t0x%04hX 0x%08X %s\n",
            name_ordinals[i],
            functions[name_ordinals[i]],
            (PCHAR)VaToPa(Idh, inh, names[i])
        );
    }
}

VOID
DumpIid32(
    _In_ PIMAGE_DOS_HEADER Idh,
    _In_ PIMAGE_NT_HEADERS32 Inh32,
    _In_ PIMAGE_IMPORT_DESCRIPTOR Iid,
	_In_ FILE *OutputFile
)
{
    PIMAGE_NT_HEADERS inh = (PIMAGE_NT_HEADERS)Inh32;

    fprintf(OutputFile, "\nPrinting from IMAGE_IMPORT_DESCRIPTOR:\n");
    fprintf(OutputFile, "\tOriginal first thunk: 0x%08X\n", Iid->OriginalFirstThunk);
    fprintf(OutputFile, "\tTime date stamp: 0x%08X\n", Iid->TimeDateStamp);
    fprintf(OutputFile, "\tForwarder chain: 0x%08X\n", Iid->ForwarderChain);
    fprintf(OutputFile, "\tName: 0x%08X (%s)\n", Iid->Name, (PCHAR)VaToPa(Idh, inh, Iid->Name));
    fprintf(OutputFile, "\tFirst thunk: 0x%08X\n\n", Iid->FirstThunk);

    fprintf(OutputFile, "\t%-10s %s\n", "Ord/Hint", "Name(opt)");
    PIMAGE_THUNK_DATA32 itd = (PIMAGE_THUNK_DATA32)VaToPa(Idh, inh, Iid->OriginalFirstThunk);
    while (itd->u1.AddressOfData != 0)
    {
        if ((itd->u1.AddressOfData & IMAGE_ORDINAL_FLAG32) == 0)
        {
            PIMAGE_IMPORT_BY_NAME iin = (PIMAGE_IMPORT_BY_NAME)VaToPa(Idh, inh, itd->u1.AddressOfData);
            fprintf(OutputFile, "\t0x%04hX     %s\n", iin->Hint, iin->Name);
        }
        else
        {
            fprintf(OutputFile, "\t0x%08X\n", itd->u1.Ordinal ^ IMAGE_ORDINAL_FLAG32);
        }
        ++itd;
    }
}

VOID
DumpIid64(
    _In_ PIMAGE_DOS_HEADER Idh,
    _In_ PIMAGE_NT_HEADERS64 Inh64,
    _In_ PIMAGE_IMPORT_DESCRIPTOR Iid,
	_In_ FILE *OutputFile
)
{
    PIMAGE_NT_HEADERS inh = (PIMAGE_NT_HEADERS)Inh64;

    fprintf(OutputFile, "\nPrinting from IMAGE_IMPORT_DESCRIPTOR:\n");
    fprintf(OutputFile, "\tOriginal first thunk: 0x%08X\n", Iid->OriginalFirstThunk);
    fprintf(OutputFile, "\tTime date stamp: 0x%08X\n", Iid->TimeDateStamp);
    fprintf(OutputFile, "\tForwarder chain: 0x%08X\n", Iid->ForwarderChain);
    fprintf(OutputFile, "\tName: 0x%08X (%s)\n", Iid->Name, (PCHAR)VaToPa(Idh, inh, Iid->Name));
    fprintf(OutputFile, "\tFirst thunk: 0x%08X\n\n", Iid->FirstThunk);

    fprintf(OutputFile, "\t%-18s %s\n", "Ord/Hint", "Name(opt)");
    PIMAGE_THUNK_DATA64 itd = (PIMAGE_THUNK_DATA64)VaToPa(Idh, inh, Iid->OriginalFirstThunk);
    while (itd->u1.AddressOfData != 0)
    {
        if ((itd->u1.AddressOfData & IMAGE_ORDINAL_FLAG64) == 0)
        {
            PIMAGE_IMPORT_BY_NAME iin = (PIMAGE_IMPORT_BY_NAME)VaToPa(Idh, inh, itd->u1.AddressOfData);
            fprintf(OutputFile, "\t0x%04hX             %s\n", iin->Hint, iin->Name);
        }
        else
        {
            fprintf(OutputFile, "\t0x%016llX\n", itd->u1.Ordinal ^ IMAGE_ORDINAL_FLAG64);
        }
        ++itd;
    }
}

VOID
DumpPE(
    _In_ PMAP FileMapped,
	_In_ PCWSTR PEFileName,
    _In_ PCWSTR OutputFileName,
    _In_ FILE *LogFile
)
{
	PIMAGE_DOS_HEADER idh;
	PIMAGE_NT_HEADERS32 inh32;
    PIMAGE_NT_HEADERS64 inh64;
    PIMAGE_EXPORT_DIRECTORY ied;
    PIMAGE_IMPORT_DESCRIPTOR iid;
    BOOL _64bit = FALSE;

	if (FileMapped == NULL)
	{
		fprintf(LogFile, "%ws: Invalid parameters!\n", PEFileName);
		return;
	}

	if (FileMapped->fileSize < sizeof(IMAGE_DOS_HEADER))
	{
		fprintf(LogFile, "%ws: sizeof(IMAGE_DOS_HEADER) > FileMapped->fileSize\n", PEFileName);
		return;
	}

	idh = (PIMAGE_DOS_HEADER)FileMapped->buffer;
	if (idh->e_magic != IMAGE_DOS_SIGNATURE)
	{
		fprintf(LogFile, "%ws: MZ signature missing!\n", PEFileName);
		return;
	}

	if (idh->e_lfanew + (DWORD)sizeof(IMAGE_NT_HEADERS) > FileMapped->fileSize)
	{
		fprintf(LogFile, "%ws: Not an executable! - idh->e_lfanew > FileMapped->fileSize\n", PEFileName);
		return;
	}

	inh32 = (PIMAGE_NT_HEADERS32)(FileMapped->buffer + idh->e_lfanew);
    inh64 = (PIMAGE_NT_HEADERS64)inh32;
    if (inh32->Signature != IMAGE_NT_SIGNATURE)
    {
        fprintf(LogFile, "%ws: Not an executable! - PE signature missing!\n", PEFileName);
		return;
    }

    if (inh32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ||
        inh32->FileHeader.Machine == IMAGE_FILE_MACHINE_IA64)
    {
        _64bit = TRUE;
    }

    if (!_64bit && inh32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0 ||
        _64bit && inh64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
    {
        ied = NULL;
    }
    else if (_64bit)
    {
        ied = (PIMAGE_EXPORT_DIRECTORY)VaToPa(
            idh,
            (PIMAGE_NT_HEADERS)inh64,
            inh64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
        );
    }
    else
    {
        ied = (PIMAGE_EXPORT_DIRECTORY)VaToPa(
            idh,
            (PIMAGE_NT_HEADERS)inh32,
            inh32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
        );
    }

    if (!_64bit && inh32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0 ||
        _64bit && inh64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
    {
        iid = NULL;
    }
    else if (_64bit)
    {
        iid = (PIMAGE_IMPORT_DESCRIPTOR)VaToPa(
            idh,
            (PIMAGE_NT_HEADERS)inh64,
            inh64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
        );
    }
    else
    {
        iid = (PIMAGE_IMPORT_DESCRIPTOR)VaToPa(
            idh,
            (PIMAGE_NT_HEADERS)inh32,
            inh32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
        );
    }

    PIMAGE_SECTION_HEADER ish = (PIMAGE_SECTION_HEADER)((PBYTE)&inh32->OptionalHeader + inh32->FileHeader.SizeOfOptionalHeader);

	FILE *outputFile;
	errno_t errOpen = _wfopen_s(&outputFile, OutputFileName, L"w");
    if (errOpen != 0)
    {
        fprintf(LogFile, "Error while opening %ws: 0x%08X\n", OutputFileName, errOpen);
        return;
    }

    DumpIdh(idh, outputFile);
    if (_64bit)
    {
        DumpIfh((PIMAGE_NT_HEADERS)inh64, outputFile);
        DumpIoh64(inh64, outputFile);
    }
    else
    {
        DumpIfh((PIMAGE_NT_HEADERS)inh32, outputFile);
        DumpIoh32(inh32, outputFile);
    }
    
    for (int i = 0; i < inh32->FileHeader.NumberOfSections; ++i, ++ish)
    {
        DumpIsh(ish, outputFile);
    }

    if (ied != NULL)
    {
        if (_64bit)
        {
            DumpIed64(idh, inh64, ied, outputFile);
        }
        else
        {
            DumpIed32(idh, inh32, ied, outputFile);
        }
    }

    if (iid != NULL)
    {
        if (_64bit)
        {
            while (iid->OriginalFirstThunk != 0)
            {
                DumpIid64(idh, inh64, iid, outputFile);
                ++iid;
            }
        }
        else
        {
            while (iid->OriginalFirstThunk != 0)
            {
                DumpIid32(idh, inh32, iid, outputFile);
                ++iid;
            }
        }    
    }

	fclose(outputFile);
	return;
}