// DumpTLB.cpp : Defines the entry point for the console application.
//
// $Log$
//

#include "stdafx.h"

#define VERSION 100

//#define BIG_ENDIAN		// Enable this line when compiling this program on big endian architecture

#ifndef BYTE
#define BYTE unsigned char
#endif

#ifndef WORD
#define WORD unsigned short
#endif

#ifndef DWORD
#define DWORD unsigned long
#endif

typedef enum {	OME_BYTES = 0,
				OME_WORDS = 1,
				OME_DWORDS = 2
} OUTPUT_MODE_ENUM;

typedef union
{
	unsigned char	raw[4];
	DWORD	dword[1];
	WORD	word[2];
	BYTE	byte[4];
} DATABUF_UNION;

typedef struct {
	const char *guid;
	const char *name;
} KNOWN_GUIDS_STRUCT;

const KNOWN_GUIDS_STRUCT KnownGuids[] = {
		{ "{00020430-0000-0000-C000-000000000046}", "TLib : OLE Automation" },
		{ "{00020400-0000-0000-C000-000000000046}", "IDispatch" },
		{ "{000204EF-0000-0000-C000-000000000046}", "Visual Basic For Applications" },
		{ "{A4C46780-499F-101B-BB78-00AA00383CBB}", "VBA Collection Object" },
		{ NULL, NULL } };

#define NUM_FILE_SECTIONS 15
const char *SectionNames[NUM_FILE_SECTIONS] = {
					"Objects Table",
					"Import Mapping Table",
					"Import Libraries Table",
					"Exposed Interfaces Table",
					"GUID Index Table (Not sure of purpose)",
					"GUID Table",
					"Type Names Index Table (Not sure of purpose)",
					"Type Names Table",
					"String Table (Help strings, enum names, etc)",
					"Object TypeCode Table",
					"???",
					"Mystery Table",
					"Weird GUID Reference Table",
					"???",
					"???"
};

typedef enum {	SNE_OBJECTS_TABLE = 0,
				SNE_IMPORT_MAPPING_TABLE = 1,
				SNE_IMPORT_LIBRARIES_TABLE = 2,
				SNE_EXPOSED_INTERFACES_TABLE = 3,
				SNE_GUID_INDEX_TABLE = 4,
				SNE_GUID_TABLE = 5,
				SNE_TYPE_NAMES_INDEX_TABLE = 6,
				SNE_TYPE_NAMES_TABLE = 7,
				SNE_STRING_TABLE = 8,
				SNE_OBJECT_TYPECODE_TABLE = 9,
				SNE_MYSTERY_TABLE = 11,
				SNE_WEIRD_GUID_REF_TABLE = 12
} SECTION_NAMES_ENUM;

typedef struct {
	DWORD	address;
	DWORD	length;
	DWORD	unknown1;
	DWORD	unknown2;
} FILE_SECTION_MAPPING_TABLE_ENTRY_STRUCT;

typedef struct {
	DWORD	address;
	DWORD	length;
	DWORD	ofs_typename;
	WORD	nMethodCount;
	WORD	nTypeCount;
} OBJECT_DATA_MAPPING_STRUCT;

typedef struct {
	DWORD	id;
	DWORD	ofs_typename;
	DWORD	ofs_typeinfo;
} OBJECT_DATA_MAPPING_ENTRY_STRUCT;

// ------------------------------------------------------------------

// The following are global to simplify memory cleanup:

	DATABUF_UNION *zData = NULL;
	DATABUF_UNION *zData2 = NULL;
	DATABUF_UNION *zData3 = NULL;
	DWORD *ObjectIndexes = NULL;

	FILE_SECTION_MAPPING_TABLE_ENTRY_STRUCT FileSectionMapping[NUM_FILE_SECTIONS];

	DWORD nObjectCount = 0;
	OBJECT_DATA_MAPPING_STRUCT *ObjectDataMapping = NULL;
	OBJECT_DATA_MAPPING_ENTRY_STRUCT *ObjectDataEntries = NULL;

	char *pTempString = NULL;

// ------------------------------------------------------------------

void PrintRepString(const char *szString, int nCount)
{
	int i;

	for (i=0; i<nCount; i++) printf(szString);
}

void SwapEndians(DATABUF_UNION zBuffer)
{
#ifdef BIG_ENDIAN		// Only swap if on different architecture
	int i;
	BYTE nTemp;

	for (i=0; i<sizeof(zBuffer); i++) {
		nTemp = zBuffer.byte[i];
		zBuffer.byte[i] = zBuffer.byte[i + sizeof(zBuffer) - 1];
		zBuffer.byte[i + sizeof(zBuffer) - 1] = nTemp;
	}
#endif
}

void WriteHeader(const char *szPathName)
{
	PrintRepString("=", 110); printf("\n");
	printf("    Decomposition of Type Library: %s\n", szPathName);
	printf("    Using DumpTLB v%d.%02d\n", (VERSION/100), (VERSION%100));
	PrintRepString("=", 110); printf("\n\n");
}

void WriteFormattedText(DWORD *nAddr, DATABUF_UNION *pzData, int nLength, int nOffset, const char *szLabel)
{
	int i;
	int bHasWrapped = 0;

	printf("%08lX", *nAddr);
	for (i=0; i<nLength; i++) {
		if (((i%32)==0) && (i!=0)) {
			bHasWrapped = 1;
			printf("\n        ");
		}
		printf(" %02X", pzData[(i+nOffset)/4].raw[(i+nOffset)%4]);
		(*nAddr)++;
	}
	if (!bHasWrapped) {
		printf(" : %s = \"", szLabel);
	} else {
		printf("\n         : %s = \"", szLabel);
	}
	for (i=0; i<nLength; i++) {
		if ((bHasWrapped) && (((i+strlen(szLabel)+6)%95)==0)) printf("\n         ");
		printf("%c", pzData[(i+nOffset)/4].raw[(i+nOffset)%4]);
	}
	printf("\"\n");
}

void WriteFormattedData(OUTPUT_MODE_ENUM nMode, DWORD *nAddr, DATABUF_UNION *pzData, int nCount, int nOffset,
						 const char *szFormat, ...)
{
	va_list args;
	int i,j;
	int nOfsBytes;
	int nUnits;

	switch (nMode) {
		case OME_BYTES:
			nUnits = 1;
			nOfsBytes = (nOffset % 4);
			break;
		case OME_WORDS:
			nUnits = 2;
			nOfsBytes = ((nOffset*2) % 4);
			break;
		case OME_DWORDS:
			nUnits = 4;
			nOfsBytes = 0;
			break;
		default:
			nUnits = 1;
			nOfsBytes = 0;
			break;
	}

	if (nCount) {
		printf("%08lX", *nAddr);
		for (i=0; i<nCount; i++) {
			printf(" ");
			for (j=0; j<nUnits; j++) {
				printf("%02X", pzData[(i+nOffset)/(4/nUnits)].raw[j+nOfsBytes]);

				(*nAddr)++;
			}

			nOfsBytes += nUnits;
			if (nOfsBytes >= 4) nOfsBytes -= 4;
		}

		if (strlen(szFormat) > 0) printf(" ");

		va_start(args, szFormat);
		vprintf(szFormat, args);
		printf("\n");
		va_end(args);
	}
}

void WriteSectionBreak(char zSep, DWORD nWidth, const char *szLabel)
{
	int nTemp;
	char szSep[2];

	if (strlen(szLabel) != 0) {
		nTemp = (nWidth - strlen(szLabel) - 2) / 2;
	} else {
		nTemp = nWidth / 2;
	}
	sprintf(szSep, "%c", zSep);

	if (strlen(szLabel) != 0) printf("\n");
	PrintRepString(szSep, nTemp);
	if (strlen(szLabel) != 0) printf(" %s ", szLabel);
	PrintRepString(szSep, nTemp);
	if (((nTemp * 2) + strlen(szLabel) + ((strlen(szLabel) != 0) ? 2 : 0)) != nWidth) printf(szSep);
	printf("\n");
	if (strlen(szLabel) != 0) printf("\n");
}

int ReadData(DATABUF_UNION **pzData, size_t nCount, FILE *zFile)
{
	if (*pzData != NULL) free(*pzData);

	if (nCount == 0) {
		*pzData = NULL;
		return 1;
	}

	*pzData = (DATABUF_UNION *)malloc(sizeof(DATABUF_UNION) * nCount);
	if (*pzData == NULL) {
		fprintf(stderr, "*** Error: Out of Memory or Memory Allocation Error!\n\n");
		fclose(zFile);
		return 0;
	}

	memset(*pzData, 0, sizeof(DATABUF_UNION) * nCount);

	if (fread(*pzData, sizeof(DATABUF_UNION), nCount, zFile) != nCount) {
		fprintf(stderr, "*** Error: Reading TLB file or unexpected EOF!\n\n");
		fclose(zFile);
		return 0;
	}

	return 1;
}

int FindFileSection(DWORD nAddr)
{
	int i;

	for (i=0; i<NUM_FILE_SECTIONS; i++) {
		if ((nAddr >= FileSectionMapping[i].address) &&
			(nAddr < (FileSectionMapping[i].address + FileSectionMapping[i].length))) return i;
	}

	for (i=0; i<(int)nObjectCount; i++) {
		if ((nAddr >= ObjectDataMapping[i].address) &&
			(nAddr < (ObjectDataMapping[i].address + ObjectDataMapping[i].length)))  return i + NUM_FILE_SECTIONS;
	}

	return -1;
}

void LookupGUID(DATABUF_UNION *pzData, char **ppszBuf)
{
	char szBuffer[128];
	const KNOWN_GUIDS_STRUCT *pKnownGuids = KnownGuids;

	sprintf(szBuffer, "{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
							pzData[0].dword[0],
							pzData[1].word[0],
							pzData[1].word[1],
							pzData[2].byte[0], pzData[2].byte[1],
							pzData[2].byte[2], pzData[2].byte[3],
							pzData[3].byte[0], pzData[3].byte[1], pzData[3].byte[2], pzData[3].byte[3]);

	while ((pKnownGuids->guid != NULL) && (pKnownGuids->name != NULL)) {
		if (strcmpi(pKnownGuids->guid, szBuffer) == 0) {
			if (*ppszBuf != NULL) free(*ppszBuf);
			*ppszBuf = (char*)malloc(strlen(pKnownGuids->name)+1);
			if (*ppszBuf != NULL) strcpy(*ppszBuf, pKnownGuids->name);
			return;
		}
		pKnownGuids++;
	}
}

char *DecodeObject(DWORD nObjectOfs, FILE *zFile, int nSearchOrder)
{
	char Buffer[1024];
	char Buffer2[1024];
	DWORD nSeekSave;
	DWORD nLocalOffset;
	DATABUF_UNION *myData = NULL;
	DATABUF_UNION *myData2 = NULL;
	char *pTemp = NULL;
	DWORD nTemp;
	int i;
	HKEY hRegKey;
	DWORD nRegType;
	DWORD nRegSize;

	strcpy(Buffer, "???");
	if (nObjectOfs == 0xFFFFFFFFul) return strdup("???");
	if (nObjectOfs == 0xFFFFFFFEul) return strdup("ThisTypeLib");
	if (nObjectOfs == 0x1ul) return strdup("IDispatch");

	nSeekSave = ftell(zFile);

	fseek(zFile, FileSectionMapping[SNE_GUID_TABLE].address, SEEK_SET);
	nLocalOffset = 0;

	nTemp = -1;
	for (i=0; ((i<(int)nObjectCount) && (nTemp == -1)); i++)
		 if (ObjectIndexes[i] == nObjectOfs) nTemp = i;

	if (nTemp != -1) {
		while (1) {
			fseek(zFile, FileSectionMapping[SNE_TYPE_NAMES_TABLE].address +
						ObjectDataMapping[nTemp].ofs_typename, SEEK_SET);
			if (!ReadData(&myData, 3, zFile)) break;

			nTemp = myData[2].byte[0];
			if (!ReadData(&myData, (nTemp+3)/4, zFile)) break;

			strncpy(Buffer, (const char*)myData, nTemp);
			Buffer[nTemp] = 0;
			break;
		}

		nLocalOffset = FileSectionMapping[SNE_GUID_TABLE].length;	// Set this to skip next loop
	}

	while (nLocalOffset < FileSectionMapping[SNE_GUID_TABLE].length) {
		if (!ReadData(&myData, 6, zFile)) break;
		nLocalOffset += 0x18ul;

		if (myData[4].dword[0] != nObjectOfs) continue;

		if (nSearchOrder) {
			LookupGUID(myData, &pTemp);
			if (pTemp) break;
		}

		sprintf(Buffer2, "Interface\\{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
								myData[0].dword[0],
								myData[1].word[0],
								myData[1].word[1],
								myData[2].byte[0], myData[2].byte[1],
								myData[2].byte[2], myData[2].byte[3],
								myData[3].byte[0], myData[3].byte[1], myData[3].byte[2], myData[3].byte[3]);

		nTemp = RegOpenKeyEx(HKEY_CLASSES_ROOT, Buffer2, 0, KEY_READ, &hRegKey);
		if (nTemp == ERROR_SUCCESS) {
			nRegSize = sizeof(Buffer2);
			nTemp = RegQueryValueEx(hRegKey, NULL, NULL, &nRegType, (unsigned char*)Buffer2, &nRegSize);
			if ((nTemp == ERROR_SUCCESS) && (nRegType == REG_SZ)) {
				strcpy(Buffer, Buffer2);
				RegCloseKey(hRegKey);
				break;
			}
			RegCloseKey(hRegKey);
		}

		LookupGUID(myData, &pTemp);
		if (pTemp) break;
	}

	fseek(zFile, nSeekSave, SEEK_SET);

	if (myData) free(myData);
	if (myData2) free(myData2);

	if (pTemp) return pTemp;
	return strdup(Buffer);
}

char *DecodeGUID(DWORD nGUIDOfs, FILE *zFile)
{
	char Buffer[1024];
	char *pTemp;
	DWORD nSeekSave;
	DATABUF_UNION *myData = NULL;

	strcpy(Buffer, "???");

	nSeekSave = ftell(zFile);
	if (nGUIDOfs == 0xFFFFFFFFul) return strdup("???");

	while (1) {
		fseek(zFile, FileSectionMapping[SNE_GUID_TABLE].address + nGUIDOfs, SEEK_SET);
		if (!ReadData(&myData, 6, zFile)) break;

		pTemp = DecodeObject(myData[4].dword[0], zFile, 1);
		sprintf(Buffer, "{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}%s%s",
							myData[0].dword[0],
							myData[1].word[0],
							myData[1].word[1],
							myData[2].byte[0], myData[2].byte[1],
							myData[2].byte[2], myData[2].byte[3],
							myData[3].byte[0], myData[3].byte[1], myData[3].byte[2], myData[3].byte[3],
							((pTemp!=NULL) ? " = " : " = ???"),
							((pTemp!=NULL) ? pTemp : ""));
		if (pTemp) free(pTemp);
		break;
	}

	fseek(zFile, nSeekSave, SEEK_SET);

	if (myData) free(myData);

	return strdup(Buffer);
}

char *DecodeVariantTypeCode(DWORD nTypeCode)
{
	char Buffer[1024];

	if ((nTypeCode & 0x7FFF) != nTypeCode) return NULL;

	if ((nTypeCode & 0xFFF) == 0xFFF) return NULL;

	Buffer[0]=0;

	if (nTypeCode & 0x1000) strcat(Buffer, "VT_VECTOR | ");
	if (nTypeCode & 0x2000) strcat(Buffer, "VT_ARRAY | ");
	if (nTypeCode & 0x4000) strcat(Buffer, "VT_BYREF | ");

	switch (nTypeCode & 0xFFFul) {
		case 0x0000:
			strcat(Buffer, "EMPTY");
			break;

		case 0x0001:
			strcat(Buffer, "NULL");
			break;

		case 0x0002:
			strcat(Buffer, "short");
			break;

		case 0x0003:
			strcat(Buffer, "long");
			break;

		case 0x0004:
			strcat(Buffer, "single");
			break;

		case 0x0005:
			strcat(Buffer, "double");
			break;

		case 0x0006:
			strcat(Buffer, "CURRENCY");
			break;

		case 0x0007:
			strcat(Buffer, "DATE");
			break;

		case 0x0008:
			strcat(Buffer, "BSTR");
			break;

		case 0x0009:
			strcat(Buffer, "IDispatch");
			break;

		case 0x000A:
			strcat(Buffer, "SCODE");
			break;

		case 0x000B:
			strcat(Buffer, "VARIANT_BOOL");
			break;

		case 0x000C:
			strcat(Buffer, "VARIANT");
			break;

		case 0x000D:
			strcat(Buffer, "IUnknown");
			break;

		case 0x000E:
			strcat(Buffer, "decimal");
			break;

		case 0x0010:
			strcat(Buffer, "char");
			break;

		case 0x0011:
			strcat(Buffer, "unsigned char");
			break;

		case 0x0012:
			strcat(Buffer, "unsigned short");
			break;

		case 0x0013:
			strcat(Buffer, "unsigned long");
			break;

		case 0x0014:
			strcat(Buffer, "__int64");
			break;

		case 0x0015:
			strcat(Buffer, "unsigned __int64");
			break;

		case 0x0016:
			strcat(Buffer, "int");
			break;

		case 0x0017:
			strcat(Buffer, "unsigned int");
			break;

		case 0x0018:
			strcat(Buffer, "void");
			break;

		case 0x0019:
			strcat(Buffer, "HRESULT");
			break;

		case 0x001A:
			strcat(Buffer, "VT_PTR");
			break;

		case 0x001B:
			strcat(Buffer, "VT_SAFEARRAY");
			break;

		case 0x001C:
			strcat(Buffer, "VT_CARRAY");
			break;

		case 0x001D:
			strcat(Buffer, "VT_USERDEFINED");
			break;

		case 0x001E:
			strcat(Buffer, "LPSTR");
			break;

		case 0x001F:
			strcat(Buffer, "LPWSTR");
			break;

		case 0x0040:
			strcat(Buffer, "FILETIME");
			break;

		case 0x0041:
			strcat(Buffer, "BLOB");
			break;

		case 0x0042:
			strcat(Buffer, "STREAM");
			break;

		case 0x0043:
			strcat(Buffer, "STORAGE");
			break;

		case 0x0044:
			strcat(Buffer, "STREAMED_OBJECT");
			break;

		case 0x0045:
			strcat(Buffer, "STORED_OBJECT");
			break;

		case 0x0046:
			strcat(Buffer, "BLOB_OBJECT");
			break;

		case 0x0047:
			strcat(Buffer, "CLIPBOARD_FORMAT");
			break;

		case 0x0048:
			strcat(Buffer, "CLSID");
			break;

		default:
			strcat(Buffer, "???");
			break;
	}

	return strdup(Buffer);
}

char *DecodeTypeCode(DWORD nTypeCode, FILE *zFile)
{
	char Buffer[1024];
	DWORD nSeekSave;
	DATABUF_UNION *myData = NULL;
	DATABUF_UNION *myData2 = NULL;
	char *pTemp;

	strcpy(Buffer, "???");

	nSeekSave = ftell(zFile);

	while (1) {
		if (nTypeCode & 0x80000000ul) {
			if (((nTypeCode & 0xFFFF0000ul)>>16) == ((nTypeCode & 0x0000FFFFul) | 0x8000ul)) {
				pTemp = DecodeVariantTypeCode(nTypeCode & 0x00007FFF);
				if (pTemp != NULL) {
					strcpy(Buffer, pTemp);
					free(pTemp);
				}
			} else {
				pTemp = DecodeVariantTypeCode((nTypeCode>>16) & 0x00007FFF);
				if (pTemp != NULL) {
					strcpy(Buffer, pTemp);
					free(pTemp);
				}

				strcat(Buffer, " ");

				pTemp = DecodeVariantTypeCode(nTypeCode & 0x00007FFF);
				if (pTemp != NULL) {
					strcat(Buffer, pTemp);
					free(pTemp);
				}
			}
		} else {
			fseek(zFile, FileSectionMapping[SNE_OBJECT_TYPECODE_TABLE].address + nTypeCode, SEEK_SET);
			if (!ReadData(&myData, 2, zFile)) break;

			switch (myData[0].word[0]) {
				case 0x001D:			// User-Defined
					pTemp = DecodeObject(myData[1].dword[0], zFile, 0);
					if (pTemp != NULL) {
						strcpy(Buffer, pTemp);
						free(pTemp);
					}
					break;

				case 0x001B:			// SAFEARRAY of
					pTemp = DecodeTypeCode(myData[1].dword[0], zFile);
					if (pTemp != NULL) {
						sprintf(Buffer, "SAFEARRAY(%s)", pTemp);
						free(pTemp);
					} else {
						strcpy(Buffer, "SAFEARRAY(???)");
					}
					break;

				case 0x001A:			// Pointer to
					pTemp = DecodeTypeCode(myData[1].dword[0], zFile);
					if (pTemp != NULL) {
						strcpy(Buffer, pTemp);
						strcat(Buffer, "*");
						free(pTemp);
					} else {
						strcpy(Buffer, "???*");
					}
					break;
			}
		}

		break;
	}

	fseek(zFile, nSeekSave, SEEK_SET);

	if (myData) free(myData);
	if (myData2) free(myData2);

	return strdup(Buffer);
}

void DumpTLB(const char *szPathName)
{
	FILE *tlbfile;

	DWORD nAddr = 0;
	int i;
	DWORD nFileLen;
	int nCurSection;
	int bInUnknown;
	int nTemp;
	int bInTypeData;
	char *pTemp;

	DWORD nSeekSave;

	tlbfile = fopen(szPathName, "rb");
	if (tlbfile == NULL) {
		fprintf(stderr, "*** Error: Opening TLB file %s for reading!\n\n", szPathName);
		return;
	}

	if (fseek(tlbfile, 0ul, SEEK_END)) {
		fprintf(stderr, "*** Error: Unable to get TLB file length via seek!\n\n");
		fclose(tlbfile);
		return;
	}

	nFileLen = (DWORD)ftell(tlbfile);
	if (nFileLen == 0xFFFFFFFFul) {
		fprintf(stderr, "*** Error: Unable to get TLB file length via ftell!\n\n");
		fclose(tlbfile);
		return;
	}

	if (fseek(tlbfile, 0ul, SEEK_SET)) {
		fprintf(stderr, "*** Error: Unable to reset TLB file to start after length check!\n\n");
		fclose(tlbfile);
		return;
	}

	if (!ReadData(&zData, 1, tlbfile)) return;
	WriteFormattedText(&nAddr, zData, 4, 0, "File Tag");

	// Make sure file starts with "MSFT" header:
	if ((zData[0].byte[0] != 0x4D) ||
		(zData[0].byte[1] != 0x53) ||
		(zData[0].byte[2] != 0x46) ||
		(zData[0].byte[3] != 0x54)) {
		printf("\n*** Error: This doesn't appear to be a standard Microsoft Type Library File!\n\n");
		fclose(tlbfile);
		return;
	}

	printf("\n");

	if (!ReadData(&zData, 2, tlbfile)) return;
	WriteFormattedData(OME_WORDS, &nAddr, zData, 4, 0, ": TLB File Format? : %d.%d.%d.%d\n",
								zData[0].word[0], zData[0].word[1], zData[1].word[0], zData[1].word[1]);

	if (!ReadData(&zData, 1, tlbfile)) return;
	WriteFormattedData(OME_WORDS, &nAddr, zData, 2, 0, ": Language Code = 0x%04X = %s\n",
								zData[0].word[0], ((zData[0].word[0] == 0x0409) ? "American English (ENU)" : "???"));

	if (!ReadData(&zData, 1, tlbfile)) return;
	WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 0, ": ???\n");

	if (!ReadData(&zData, 1, tlbfile)) return;
	WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 0, ": ???\n");

	if (!ReadData(&zData, 1, tlbfile)) return;
	WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 0, ": Library Version Major = 0x%04X = %d", zData[0].word[0], zData[0].word[0]);
	WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 1, ": Library Version Minor = 0x%04X = %d\n", zData[0].word[1], zData[0].word[1]);

	if (!ReadData(&zData, 1, tlbfile)) return;
	WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 0, ": ???\n");

	if (!ReadData(&zData, 1, tlbfile)) return;
	WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 0, ": Count = %ld\n", zData[0].dword[0]);
	nObjectCount = zData[0].dword[0];

	for (i=0; i<3; i++) {
		if (!ReadData(&zData, 4, tlbfile)) return;
		WriteFormattedData(OME_DWORDS, &nAddr, zData, 4, 0, "");
	}

	WriteSectionBreak('=', 110, "Objects Index Table");

	ObjectIndexes = (DWORD *)malloc(sizeof(DWORD) * nObjectCount);
	ObjectDataMapping = (OBJECT_DATA_MAPPING_STRUCT *)malloc(sizeof(OBJECT_DATA_MAPPING_STRUCT) * nObjectCount);
	if ((ObjectIndexes == NULL) || (ObjectDataMapping == NULL)) {
		fprintf(stderr, "*** Error: Out of Memory or Memory Allocation Error!\n\n");
		fclose(tlbfile);
		return;
	}

	for (i=0; (DWORD)i<nObjectCount; i++) {
		if (!ReadData(&zData, 1, tlbfile)) return;
		WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 0, ": Offset = %ld", zData[0].dword[0]);
		ObjectIndexes[i] = zData[0].dword[0];

		// Clear mapping info until we've processed the objects:
		ObjectDataMapping[i].address = 0;
		ObjectDataMapping[i].length = 0;
		ObjectDataMapping[i].ofs_typename = 0;
		ObjectDataMapping[i].nMethodCount = 0;
		ObjectDataMapping[i].nTypeCount = 0;
	}

	WriteSectionBreak('=', 110, "File Section Table");

	for (i=0; i<NUM_FILE_SECTIONS; i++) {
		if (!ReadData(&zData, 4, tlbfile)) return;
		if (zData[0].dword[0] != 0xFFFFFFFFul) {
			WriteFormattedData(OME_DWORDS, &nAddr, zData, 4, 0, ": Addr: 0x%08lX  Length: 0x%04lX : %s",
											zData[0].dword[0], zData[1].dword[0], SectionNames[i]);
		} else {
			WriteFormattedData(OME_DWORDS, &nAddr, zData, 4, 0, ":         <Doesn't Exist>          : %s",
											SectionNames[i]);
		}
		FileSectionMapping[i].address = zData[0].dword[0];
		FileSectionMapping[i].length = zData[1].dword[0];
		FileSectionMapping[i].unknown1 = zData[2].dword[0];
		FileSectionMapping[i].unknown2 = zData[3].dword[0];
	}

	nSeekSave = ftell(tlbfile);

	// Iterate over objects table and find object data mapping:
	for (i=0; i<(int)nObjectCount; i++) {
		fseek(tlbfile, FileSectionMapping[SNE_OBJECTS_TABLE].address + ObjectIndexes[i], SEEK_SET);
		if (!ReadData(&zData, 25, tlbfile)) return;
		if ((zData[6].word[0] != 0) ||
			(zData[6].word[1] != 0)) {
			ObjectDataMapping[i].address = zData[1].dword[0];
			// Note: Below doesn't calculate the full length of the object's data section because we
			//			don't know the rest without seeking to the data section.  However, we do
			//			know that each method and typedef entry has 3 corresponding long integer
			//			entries in the tables.  And, there are 4 bytes for the data length value.
			//			These rest we'll calculate and add to this length when we process the data section:
			ObjectDataMapping[i].length = ((zData[6].word[0] + zData[6].word[1]) * 12) + 4;
		}
		ObjectDataMapping[i].ofs_typename = zData[13].dword[0];
		ObjectDataMapping[i].nMethodCount = zData[6].word[0];
		ObjectDataMapping[i].nTypeCount = zData[6].word[1];
	}

	fseek(tlbfile, nSeekSave, SEEK_SET);

	bInUnknown = 0;
	bInTypeData = 0;
	while (nAddr < nFileLen) {
		nCurSection = FindFileSection(nAddr);

		if (nCurSection == -1) {
			bInTypeData=0;

			i=1;
			if (FindFileSection(nAddr+0x4) == -1) {
				i++;
				if (FindFileSection(nAddr+0x8) == -1) {
					i++;
					if (FindFileSection(nAddr+0xC) == -1) {
						i++;
					}
				}
			}

			if ((nAddr + (i * 4)) >= nFileLen) i = (nFileLen - nAddr)/4;

			if (bInUnknown == 0) printf("\n");
			bInUnknown = 1;
			if (!ReadData(&zData, i, tlbfile)) return;
			WriteFormattedData(OME_BYTES, &nAddr, zData, i*4, 0, "");
		} else {
			bInUnknown = 0;

			if (nCurSection < NUM_FILE_SECTIONS) {
				bInTypeData = 0;

				if (nAddr == FileSectionMapping[nCurSection].address) WriteSectionBreak('=', 110, SectionNames[nCurSection]);

				switch (nCurSection) {
					case SNE_OBJECTS_TABLE:
						if (!ReadData(&zData, 25, tlbfile)) return;

						nSeekSave = ftell(tlbfile);

						fseek(tlbfile, FileSectionMapping[SNE_TYPE_NAMES_TABLE].address +
										zData[13].dword[0], SEEK_SET);
						if (!ReadData(&zData2, 3, tlbfile)) return;
						nTemp = zData2[2].byte[0];
						if (!ReadData(&zData2, (nTemp+3)/4, tlbfile)) return;

						pTempString = (char *)malloc(nTemp+1);
						if (pTempString == NULL) {
							fprintf(stderr, "*** Error: Out of Memory or Memory Allocation Error!\n\n");
							fclose(tlbfile);
							return;
						}
						strncpy(pTempString, (const char*)zData2, nTemp);
						pTempString[nTemp] = 0;

						printf("Offset %ld : %s\n", (nAddr - FileSectionMapping[nCurSection].address), pTempString);
						WriteSectionBreak('-', 40, "");

						WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 0, "    : Type Code = 0x%04X", zData[0].word[0]);
						WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 1, "    : Item Index = %d", zData[0].word[1]);
						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 1, ": Address = 0x%04lX", zData[1].dword[0]);
						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 2, ": 0x%04lX", zData[2].dword[0]);
						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 3, ": 0x%04lX", zData[3].dword[0]);
						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 4, "");
						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 5, "");
						WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 12, "    : Method Item Count = %d", zData[6].word[0]);
						WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 13, "    : TypeDef Item Count = %d", zData[6].word[1]);
						WriteFormattedData(OME_DWORDS, &nAddr, zData, 4, 7, "");

						if (zData[11].dword[0] != 0xFFFFFFFFul) {
							pTemp = DecodeGUID(zData[11].dword[0], tlbfile);

							WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 11, ": GUID Table Offset = 0x%04lX = %s",
												zData[11].dword[0],
												((pTemp != NULL) ? pTemp : "???"));
							if (pTemp) free(pTemp);
						} else {
							WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 11, ": GUID Table Offset = -1 = <NONE>");
						}

						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 12, "");
						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 13, ": Type Names Table Offset = 0x%04lX = \"%s\"",
											zData[13].dword[0], pTempString);
						if (pTempString) {
							free(pTempString);
							pTempString = NULL;
						}

						WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 28, "    : Version Major = %d", zData[14].word[0]);
						WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 29, "    : Version Minor = %d", zData[14].word[1]);

						if (zData[15].dword[0] != 0xFFFFFFFFul) {
							fseek(tlbfile, FileSectionMapping[SNE_STRING_TABLE].address +
											zData[15].dword[0], SEEK_SET);
							if (!ReadData(&zData2, 1, tlbfile)) return;
							nTemp = zData2[0].word[0];
							fseek(tlbfile, FileSectionMapping[SNE_STRING_TABLE].address +
											zData[15].dword[0] + 2, SEEK_SET);
							if (!ReadData(&zData2, (nTemp+5)/4, tlbfile)) return;

							pTempString = (char *)malloc(nTemp+1);
							if (pTempString == NULL) {
								fprintf(stderr, "*** Error: Out of Memory or Memory Allocation Error!\n\n");
								fclose(tlbfile);
								return;
							}
							strncpy(pTempString, (const char*)zData2, nTemp);
							pTempString[nTemp] = 0;

							WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 15, ": HelpString : String Table Offset = 0x%04lX = \"%s\"",
															zData[15].dword[0], pTempString);
						} else {
							WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 15, ": HelpString : String Table Offset = -1 = <NONE>");
						}
						if (pTempString) {
							free(pTempString);
							pTempString = NULL;
						}

						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 16, "");
						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 17, "");
						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 18, "");

						WriteFormattedData(OME_WORDS, &nAddr, zData, 10, 38, "");

						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 24, "");
						printf("\n");

						fseek(tlbfile, nSeekSave, SEEK_SET);
						break;

					case SNE_GUID_INDEX_TABLE:
						if (!ReadData(&zData, 1, tlbfile)) return;

						if (pTempString) {
							free(pTempString);
							pTempString = NULL;
						}

						if (zData[0].dword[0] != 0xFFFFFFFFul) {
							pTempString = DecodeGUID(zData[0].dword[0], tlbfile);

							WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 0, ": GUID Table Offset = 0x%04lX = %s",
												zData[0].dword[0],
												((pTempString!=NULL) ? pTempString : "???"));
						} else {
							WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 0, "");
						}

						if (pTempString) {
							free(pTempString);
							pTempString = NULL;
						}
						break;

					case SNE_GUID_TABLE:
						printf("GUID: 0x%08lX:\n", (nAddr - FileSectionMapping[SNE_GUID_TABLE].address));
						WriteSectionBreak('-', 40, "");

						if (!ReadData(&zData, 6, tlbfile)) return;

						if (pTempString) {
							free(pTempString);
							pTempString = NULL;
						}

						pTempString = DecodeGUID((nAddr - FileSectionMapping[SNE_GUID_TABLE].address), tlbfile);

						WriteFormattedData(OME_DWORDS, &nAddr, zData, 4, 0,
											": %s",
											((pTempString!=NULL) ? pTempString : "???"));
						if (pTempString) {
							free(pTempString);
							pTempString = NULL;
						}

						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 4, "                           : Object Offset = %ld",
											zData[4].dword[0]);
						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 5, "                           : 0x%04lX (%ld)",
											zData[5].dword[0], zData[5].dword[0]);
						printf("\n");
						break;

					case SNE_EXPOSED_INTERFACES_TABLE:
						if (!ReadData(&zData, 4, tlbfile)) return;

						if (pTempString) {
							free(pTempString);
							pTempString = NULL;
						}

						pTempString = DecodeObject(zData[0].dword[0], tlbfile, 0);

						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 0,
											": Offset = %ld%s%s",
											zData[0].dword[0],
											((pTempString!=NULL) ? " = " : ""),
											((pTempString!=NULL) ? pTempString : ""));
						if (pTempString) {
							free(pTempString);
							pTempString = NULL;
						}

						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 1, ": 0x%04lX",
											zData[1].dword[0], zData[1].dword[0]);
						WriteFormattedData(OME_DWORDS, &nAddr, zData, 2, 2, "");
						printf("\n");
						break;

					case SNE_IMPORT_MAPPING_TABLE:
						if (!ReadData(&zData, 3, tlbfile)) return;

						nSeekSave = ftell(tlbfile);

						WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 0, "    : Index = %d",
											zData[0].word[0]);
						WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 1, "");

						if (pTempString) {
							free(pTempString);
							pTempString = NULL;
						}

						fseek(tlbfile, FileSectionMapping[SNE_IMPORT_LIBRARIES_TABLE].address +
										zData[1].dword[0], SEEK_SET);
						if (!ReadData(&zData2, 1, tlbfile)) return;

						pTempString = DecodeGUID(zData2[0].dword[0], tlbfile);

						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 1, ": Import Libraries Table Offset = 0x%04lX%s%s",
														zData[1].dword[0],
														((pTempString != NULL) ? " = " : " = ???"),
														((pTempString != NULL) ? pTempString : ""));

						if (pTempString) {
							free(pTempString);
							pTempString = NULL;
						}

						pTempString = DecodeGUID(zData[2].dword[0], tlbfile);

						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 2, ": GUID Table Offset = 0x%04lX%s%s",
														zData[2].dword[0],
														((pTempString != NULL) ? " = " : " = ???"),
														((pTempString != NULL) ? pTempString : ""));

						if (pTempString) {
							free(pTempString);
							pTempString = NULL;
						}

						printf("\n");

						fseek(tlbfile, nSeekSave, SEEK_SET);
						break;

					case SNE_IMPORT_LIBRARIES_TABLE:
						if (!ReadData(&zData, 3, tlbfile)) return;

						nSeekSave = ftell(tlbfile);

						if (pTempString) {
							free(pTempString);
							pTempString = NULL;
						}

						pTempString = DecodeGUID(zData[0].dword[0], tlbfile);

						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 0, ": GUID Table Offset = 0x%04lX%s%s",
														zData[0].dword[0],
														((pTempString != NULL) ? " = " : " = ???"),
														((pTempString != NULL) ? pTempString : ""));
						if (pTempString) {
							free(pTempString);
							pTempString = NULL;
						}

						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 1, ": ???");
						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 2, ": ???");

						fseek(tlbfile, nSeekSave, SEEK_SET);
						if (!ReadData(&zData, 1, tlbfile)) return;
						fseek(tlbfile, nSeekSave, SEEK_SET);
						if (!ReadData(&zData, (((zData[0].word[0]/4)+5)/4), tlbfile)) return;

						nTemp = (zData[0].word[0]/4);

						WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 0, "    : Filename Length * 4??? = %d",
												nTemp);

						pTempString = (char *)malloc(nTemp+1);
						if (pTempString == NULL) {
							fprintf(stderr, "*** Error: Out of Memory or Memory Allocation Error!\n\n");
							fclose(tlbfile);
							return;
						}
						strncpy(pTempString, (const char*)(&zData[0].byte[2]), nTemp);
						pTempString[nTemp] = 0;
						WriteFormattedData(OME_BYTES, &nAddr, zData, nTemp, 2, ": Filename = \"%s\"", pTempString);

						free(pTempString);
						if ((((((zData[0].word[0]/4)+5)/4)*4)-nTemp-2) != 0) {
							pTempString = (char *)malloc(((((zData[0].word[0]/4)+5)/4)*4)-nTemp-2+1);
							if (pTempString == NULL) {
								fprintf(stderr, "*** Error: Out of Memory or Memory Allocation Error!\n\n");
								fclose(tlbfile);
								return;
							}
							strncpy(pTempString, (const char*)(&zData[0].byte[2])+nTemp, ((((zData[0].word[0]/4)+5)/4)*4)-nTemp-2);
							pTempString[((((zData[0].word[0]/4)+5)/4)*4)-nTemp-2] = 0;
							WriteFormattedData(OME_BYTES, &nAddr, zData, ((((zData[0].word[0]/4)+5)/4)*4)-nTemp-2, nTemp+2, ": DWord Boundary Padding = \"%s\"", pTempString);
						}
						if (pTempString) {
							free(pTempString);
							pTempString = NULL;
						}

						printf("\n");

						break;

					case SNE_TYPE_NAMES_INDEX_TABLE:
						if (!ReadData(&zData, 1, tlbfile)) return;

						nSeekSave = ftell(tlbfile);

						if (zData[0].dword[0] != 0xFFFFFFFFul) {

							if (pTempString) {
								free(pTempString);
								pTempString = NULL;
							}

							fseek(tlbfile, FileSectionMapping[SNE_TYPE_NAMES_TABLE].address +
											zData[0].dword[0], SEEK_SET);
							if (!ReadData(&zData2, 3, tlbfile)) return;
							nTemp = zData2[2].byte[0];
							if (!ReadData(&zData2, (nTemp+3)/4, tlbfile)) return;

							pTempString = (char *)malloc(nTemp+1);
							if (pTempString == NULL) {
								fprintf(stderr, "*** Error: Out of Memory or Memory Allocation Error!\n\n");
								fclose(tlbfile);
								return;
							}
							strncpy(pTempString, (const char*)zData2, nTemp);
							pTempString[nTemp] = 0;

							WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 0, ": Type Names Table Offset = 0x%04lX = \"%s\"",
												zData[0].dword[0], pTempString);
						} else {
							WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 0, "");
						}

						if (pTempString) {
							free(pTempString);
							pTempString = NULL;
						}

						fseek(tlbfile, nSeekSave, SEEK_SET);
						break;

					case SNE_TYPE_NAMES_TABLE:
						printf("Type Name: 0x%08lX:\n", (nAddr - FileSectionMapping[SNE_TYPE_NAMES_TABLE].address));
						WriteSectionBreak('-', 40, "");

						if (!ReadData(&zData, 3, tlbfile)) return;

						nSeekSave = ftell(tlbfile);

						if (zData[0].dword[0] != 0xFFFFFFFFul) {
							nTemp = -1;
							for (i=0; ((i<(int)nObjectCount) && (nTemp == -1)); i++)
								 if (ObjectIndexes[i] == zData[0].dword[0]) nTemp = i;

							if (nTemp != -1) {
								fseek(tlbfile, FileSectionMapping[SNE_TYPE_NAMES_TABLE].address +
											ObjectDataMapping[nTemp].ofs_typename, SEEK_SET);
								if (!ReadData(&zData2, 3, tlbfile)) return;
								nTemp = zData2[2].byte[0];
								if (!ReadData(&zData2, (nTemp+3)/4, tlbfile)) return;

								pTempString = (char *)malloc(nTemp+1);
								if (pTempString == NULL) {
									fprintf(stderr, "*** Error: Out of Memory or Memory Allocation Error!\n\n");
									fclose(tlbfile);
									return;
								}
								strncpy(pTempString, (const char*)zData2, nTemp);
								pTempString[nTemp] = 0;
							} else {
								if (pTempString) {
									free(pTempString);
									pTempString = NULL;
								}
							}

							WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 0, ": Offset = %ld = %s",
												zData[0].dword[0],
												((pTempString!=NULL) ? pTempString : "???"));
						} else {
							WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 0, ": Offset = -1");
						}

						if (pTempString) {
							free(pTempString);
							pTempString = NULL;
						}

						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 1, ": 0x%04lX = ???",
												zData[1].dword[0]);

						WriteFormattedData(OME_BYTES, &nAddr, zData, 1, 8, "      : Name Length = %d",
												zData[2].byte[0]);

						WriteFormattedData(OME_BYTES, &nAddr, zData, 3, 9, ": ???");

						fseek(tlbfile, nSeekSave, SEEK_SET);
						nTemp = zData[2].byte[0];
						if (!ReadData(&zData2, (nTemp+3)/4, tlbfile)) return;

						pTempString = (char *)malloc(nTemp+1);
						if (pTempString == NULL) {
							fprintf(stderr, "*** Error: Out of Memory or Memory Allocation Error!\n\n");
							fclose(tlbfile);
							return;
						}
						strncpy(pTempString, (const char*)zData2, nTemp);
						pTempString[nTemp] = 0;

						// WriteFormattedData(OME_BYTES, &nAddr, zData2, nTemp, 0, ": Name = \"%s\"", pTempString);
						WriteFormattedText(&nAddr, zData2, nTemp, 0, "Name");

						free(pTempString);

						pTempString = (char *)malloc((((nTemp+3)/4)*4) - nTemp + 1);
						if (pTempString == NULL) {
							fprintf(stderr, "*** Error: Out of Memory or Memory Allocation Error!\n\n");
							fclose(tlbfile);
							return;
						}
						strncpy(pTempString, (const char*)(zData2) + nTemp, (((nTemp+3)/4)*4) - nTemp);
						pTempString[(((nTemp+3)/4)*4) - nTemp] = 0;

						WriteFormattedData(OME_BYTES, &nAddr, zData2, (((nTemp+3)/4)*4) - nTemp, nTemp,
												": DWord Boundary Padding = \"%s\"", pTempString);

						free(pTempString);
						pTempString = NULL;

						printf("\n");
						break;

					case SNE_STRING_TABLE:
						printf("String: 0x%08lX:\n", (nAddr - FileSectionMapping[SNE_STRING_TABLE].address));
						WriteSectionBreak('-', 40, "");

						nSeekSave = ftell(tlbfile);
						if (!ReadData(&zData, 1, tlbfile)) return;
						fseek(tlbfile, nSeekSave, SEEK_SET);

						nTemp = zData[0].word[0];

						WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 0, ":  Length = %d", nTemp);

						if (pTempString) {
							free(pTempString);
							pTempString = NULL;
						}

						if (!ReadData(&zData, (nTemp+5)/4, tlbfile)) return;

						pTempString = (char *)malloc(nTemp+1);
						if (pTempString == NULL) {
							fprintf(stderr, "*** Error: Out of Memory or Memory Allocation Error!\n\n");
							fclose(tlbfile);
							return;
						}
						strncpy(pTempString, (const char*)(zData) + 2, nTemp);
						pTempString[nTemp] = 0;

						// WriteFormattedData(OME_BYTES, &nAddr, zData, nTemp, 2, ": String = \"%s\"", pTempString);
						WriteFormattedText(&nAddr, zData, nTemp, 2, "String");

						free(pTempString);

						pTempString = (char *)malloc((((nTemp+5)/4)*4) - nTemp-2 + 1);
						if (pTempString == NULL) {
							fprintf(stderr, "*** Error: Out of Memory or Memory Allocation Error!\n\n");
							fclose(tlbfile);
							return;
						}
						strncpy(pTempString, (const char*)(zData) + nTemp+2, (((nTemp+5)/4)*4) - nTemp-2);
						pTempString[(((nTemp+5)/4)*4) - nTemp-2] = 0;

						WriteFormattedData(OME_BYTES, &nAddr, zData, (((nTemp+5)/4)*4) - nTemp-2, nTemp+2,
												": DWord Boundary Padding = \"%s\"", pTempString);

						free(pTempString);
						pTempString = NULL;

						printf("\n");
						break;

					case SNE_OBJECT_TYPECODE_TABLE:
						if (!ReadData(&zData, 2, tlbfile)) return;

						nSeekSave = ftell(tlbfile);

						printf("Type Code: 0x%08lX:\n", (nAddr - FileSectionMapping[SNE_OBJECT_TYPECODE_TABLE].address));
						WriteSectionBreak('-', 40, "");

						pTemp = DecodeVariantTypeCode(zData[0].word[0]);
						WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 0, "    : Type Identifier = 0x%04X%s%s",
															zData[0].word[0],
															((pTemp != NULL) ? " = " : ""),
															((pTemp != NULL) ? pTemp : ""));
						if (pTemp) free(pTemp);

						pTemp = DecodeVariantTypeCode(zData[0].word[1]);
						WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 1, "    : Base Type = 0x%04X%s%s",
															zData[0].word[1],
															((pTemp != NULL) ? " = " : ""),
															((pTemp != NULL) ? pTemp : ""));
						if (pTemp) free(pTemp);

						if (pTempString) {
							free(pTempString);
							pTempString = NULL;
						}

						switch (zData[0].word[0]) {
							case (0x001D):						// User-Defined
								pTempString = DecodeObject(zData[1].dword[0], tlbfile, 0);

								WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 1,
													": Offset = %ld%s%s",
													zData[1].dword[0],
													((pTempString!=NULL) ? " = " : ""),
													((pTempString!=NULL) ? pTempString : ""));
								break;

							case (0x001B):						// SafeArray
								pTemp = DecodeTypeCode(zData[1].dword[0], tlbfile);
								WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 1,
													": Type Code: 0x%08lX = SAFEARRAY(%s)", zData[1].dword[0],
													((pTemp != NULL) ? pTemp : "???"));
								if (pTemp) free(pTemp);
								break;

							case (0x001A):						// PTR
								pTemp = DecodeTypeCode(zData[1].dword[0], tlbfile);
								WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 1,
													": Type Code: 0x%08lX = %s*", zData[1].dword[0],
													((pTemp != NULL) ? pTemp : "???"));
								if (pTemp) free(pTemp);
								break;

							default:
								WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 1,
													": ??? = 0x%04lX (%ld)",
													zData[1].dword[0], zData[1].dword[0]);
								break;
						}

						if (pTempString) {
							free(pTempString);
							pTempString = NULL;
						}

						printf("\n");

						fseek(tlbfile, nSeekSave, SEEK_SET);
						break;

					case SNE_WEIRD_GUID_REF_TABLE:
						if (!ReadData(&zData, 3, tlbfile)) return;

						if (pTempString) {
							free(pTempString);
							pTempString = NULL;
						}

						pTempString = DecodeGUID(zData[0].dword[0], tlbfile);

						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 0, ": GUID Table Offset = 0x%04lX = %s",
												zData[0].dword[0],
												((pTempString!=NULL) ? pTempString : "???"));

						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 1, ": ??? = 0x%04lX (%ld)",
												zData[1].dword[0], zData[1].dword[0]);

						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 2, ": ??? = 0x%04lX (%ld)",
												zData[2].dword[0], zData[2].dword[0]);

						if (pTempString) {
							free(pTempString);
							pTempString = NULL;
						}

						printf("\n");
						break;

					case SNE_MYSTERY_TABLE:
						if (!ReadData(&zData, 2, tlbfile)) return;

						WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 0, ": ??? = 0x%04X (%d)",
												zData[0].word[0], zData[0].word[0]);

						WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 1, ": ??? = 0x%04X (%d)",
												zData[0].word[1], zData[0].word[1]);

						WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 2, ": ??? = 0x%04X (%d)",
												zData[1].word[0], zData[1].word[0]);

						WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 3, ": ??? = 0x%04X (%d)",
												zData[1].word[1], zData[1].word[1]);

						printf("\n");
						break;

					default:
						i=1;
						if (FindFileSection(nAddr+0x4) == nCurSection) {
							i++;
							if (FindFileSection(nAddr+0x8) == nCurSection) {
								i++;
								if (FindFileSection(nAddr+0xC) == nCurSection) {
									i++;
								}
							}
						}

						if (!ReadData(&zData, i, tlbfile)) return;
						WriteFormattedData(OME_DWORDS, &nAddr, zData, i, 0, "");
						break;
				};

			} else {
				if (bInTypeData == 0) {
					WriteSectionBreak('=', 110, "Type Data Information");
					bInTypeData = 1;
				}

				OBJECT_DATA_MAPPING_STRUCT *pObjectData = &ObjectDataMapping[nCurSection - NUM_FILE_SECTIONS];
				OBJECT_DATA_MAPPING_ENTRY_STRUCT *pObjectEntry;
				DWORD nInfoSize;
				DWORD nLocalOffset;
				DWORD nItemCount;
				DWORD nSubItemCount;
				DWORD nEntrySize;
				DWORD nTypeCode;

				nSeekSave = ftell(tlbfile);

				if (pTempString) {
					free(pTempString);
					pTempString = NULL;
				}

				fseek(tlbfile, FileSectionMapping[SNE_TYPE_NAMES_TABLE].address +
											pObjectData->ofs_typename, SEEK_SET);
				if (!ReadData(&zData3, 3, tlbfile)) return;
				nTemp = zData3[2].byte[0];
				if (!ReadData(&zData3, (nTemp+3)/4, tlbfile)) return;

				pTempString = (char *)malloc(nTemp+1);
				if (pTempString == NULL) {
					fprintf(stderr, "*** Error: Out of Memory or Memory Allocation Error!\n\n");
					fclose(tlbfile);
					return;
				}
				strncpy(pTempString, (const char*)zData3, nTemp);
				pTempString[nTemp] = 0;

				WriteSectionBreak('=', 80, pTempString);
				free(pTempString);
				pTempString = NULL;

				fseek(tlbfile, nSeekSave, SEEK_SET);
				if (!ReadData(&zData, 1, tlbfile)) return;
				nSeekSave = ftell(tlbfile);

				nInfoSize = zData[0].dword[0];

				WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 0, ": Size of Type Info Below = 0x%04lX (%ld)\n",
																nInfoSize, nInfoSize);
				pObjectData->length += nInfoSize;

				nItemCount = pObjectData->nMethodCount + pObjectData->nTypeCount;
				ObjectDataEntries = (OBJECT_DATA_MAPPING_ENTRY_STRUCT*)malloc(sizeof(OBJECT_DATA_MAPPING_ENTRY_STRUCT)*
													nItemCount);
				if (ObjectDataEntries == NULL) {
					fprintf(stderr, "*** Error: Out of Memory or Memory Allocation Error!\n\n");
					fclose(tlbfile);
					return;
				}

				fseek(tlbfile, nSeekSave + nInfoSize, SEEK_SET);
				if (!ReadData(&zData, nItemCount*3, tlbfile)) return;

				for (i=0; (DWORD)i<nItemCount; i++) {
					ObjectDataEntries[i].id = zData[i].dword[0];
					ObjectDataEntries[i].ofs_typename = zData[nItemCount+i].dword[0];
					ObjectDataEntries[i].ofs_typeinfo = zData[nItemCount*2+i].dword[0];
				}

				fseek(tlbfile, nSeekSave, SEEK_SET);

				nLocalOffset = 0ul;
				while (nLocalOffset < nInfoSize) {
					pObjectEntry = NULL;
					for (i=0; (((DWORD)i<nItemCount) && (pObjectEntry==NULL)); i++) {
						if (nLocalOffset == ObjectDataEntries[i].ofs_typeinfo) pObjectEntry = &ObjectDataEntries[i];
					}

					nSeekSave = ftell(tlbfile);

					if ((pObjectEntry) && (pObjectEntry->ofs_typename != 0xFFFFFFFFul)) {
						fseek(tlbfile, FileSectionMapping[SNE_TYPE_NAMES_TABLE].address +
													pObjectEntry->ofs_typename, SEEK_SET);
						if (!ReadData(&zData3, 3, tlbfile)) return;
						nTemp = zData3[2].byte[0];
						if (!ReadData(&zData3, (nTemp+3)/4, tlbfile)) return;

						pTempString = (char *)malloc(nTemp+1);
						if (pTempString == NULL) {
							fprintf(stderr, "*** Error: Out of Memory or Memory Allocation Error!\n\n");
							fclose(tlbfile);
							return;
						}
						strncpy(pTempString, (const char*)zData3, nTemp);
						pTempString[nTemp] = 0;

						printf("Offset 0x%04lX = %s:\n", nLocalOffset, pTempString);

						free(pTempString);
						pTempString = NULL;
					} else {
						printf("Offset 0x%04lX = ???:\n", nLocalOffset);
					}
					WriteSectionBreak('-', 60, "");

					fseek(tlbfile, nSeekSave, SEEK_SET);

					if (!ReadData(&zData, 1, tlbfile)) return;

					WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 0, "    : Size = 0x%04X", zData[0].word[0]);
					nLocalOffset += zData[0].word[0];

					nEntrySize = zData[0].word[0];

					WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 1, "    : Index = %d", zData[0].word[1]);

					if (nEntrySize >= 0x18) {
						if (!ReadData(&zData2, 5, tlbfile)) return;
					} else {
						if (!ReadData(&zData2, (nEntrySize/4)-1, tlbfile)) return;
					}

					if (nEntrySize >= 0x18) {
						nSubItemCount = zData2[4].word[0];
					} else {
						nSubItemCount = 0;
					}

					if (nEntrySize >= 0x08) {
						nTypeCode = zData2[0].dword[0];
						pTemp = DecodeTypeCode(nTypeCode, tlbfile);
						WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 0, ": Type Code: 0x%08lX = %s", zData2[0].dword[0], ((pTemp != NULL) ? pTemp : "???"));
						if (pTemp) free(pTemp);
					}

					if (nEntrySize >= 0x0C) {
						WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 1, "");
					}

					if (nEntrySize >= 0x10) {
						WriteFormattedData(OME_WORDS, &nAddr, zData2, 1, 4, "    : ??? = 0x%04X (%d)",
													 zData2[2].word[0], zData2[2].word[0]);
						WriteFormattedData(OME_WORDS, &nAddr, zData2, 1, 5, "    : ??? = 0x%04X (%d)",
													 zData2[2].word[1], zData2[2].word[1]);
					}

					if (nEntrySize >= 0x14) {
						switch (nTypeCode & 0x8000FFFFul) {
							case 0x80000016ul:
								WriteFormattedData(OME_WORDS, &nAddr, zData2, 1, 6, "    : Index = %d", zData2[3].word[0]);
								break;
							default:
								WriteFormattedData(OME_WORDS, &nAddr, zData2, 1, 6, "    : ??? = 0x%04X (%d)",
															 zData2[3].word[0], zData2[3].word[0]);
								break;
						}
						switch (nTypeCode & 0x8000FFFFul) {
							case 0x80000019ul:
								WriteFormattedData(OME_WORDS, &nAddr, zData2, 1, 7, "    : Index = %d", zData2[3].word[1]);
								break;
							default:
								WriteFormattedData(OME_WORDS, &nAddr, zData2, 1, 7, "    : ??? = 0x%04X (%d)",
															 zData2[3].word[1], zData2[3].word[1]);
								break;
						}
					}

					if (nEntrySize >= 0x18) {
						WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 4, ": Argument Count = %d", nSubItemCount);
					} else {
						printf("                  : Argument Count = %d\n", nSubItemCount);
					}

					if ((nEntrySize >= 0x18) && ((nEntrySize - 0x18) > (nSubItemCount * 0x0C))) {
						if (!ReadData(&zData2, ((nEntrySize - 0x18 - (nSubItemCount * 0x0C))/4), tlbfile)) return;

						nSeekSave = ftell(tlbfile);

						switch (nTypeCode & 0x8000FFFFul) {
							case 0x80000019ul:
								WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 0, "");

								if (((nEntrySize - 0x18 - (nSubItemCount * 0x0C))/4) >= 2) {
									if ((zData2[1].dword[0] != 0xFFFFFFFFul) &&
										((zData2[1].dword[0] & 0x80000000ul) == 0)) {
										fseek(tlbfile, FileSectionMapping[SNE_STRING_TABLE].address +
														zData2[1].dword[0], SEEK_SET);
										if (!ReadData(&zData3, 1, tlbfile)) return;
										nTemp = zData3[0].word[0];
										fseek(tlbfile, FileSectionMapping[SNE_STRING_TABLE].address +
														zData2[1].dword[0] + 2, SEEK_SET);
										if (!ReadData(&zData3, (nTemp+5)/4, tlbfile)) return;

										pTempString = (char *)malloc(nTemp+1);
										if (pTempString == NULL) {
											fprintf(stderr, "*** Error: Out of Memory or Memory Allocation Error!\n\n");
											fclose(tlbfile);
											return;
										}
										strncpy(pTempString, (const char*)zData3, nTemp);
										pTempString[nTemp] = 0;

										WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 1, ": HelpString : String Table Offset = 0x%04lX = \"%s\"",
																		zData2[1].dword[0], pTempString);
									} else {
										if (zData2[1].dword[0] == 0xFFFFFFFFul) {
											WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 1, ": HelpString : String Table Offset = -1 = <NONE>");
										} else {
											WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 1, ": ??? = 0x%04lX (%ld)",
																		zData2[1].dword[0], zData2[1].dword[0]);
										}
									}

									if (pTempString) {
										free(pTempString);
										pTempString = NULL;
									}
								}

								if (((nEntrySize - 0x18 - (nSubItemCount * 0x0C))/4) >= 3) {
									WriteFormattedData(OME_DWORDS, &nAddr, zData2, ((nEntrySize - 0x18 - (nSubItemCount * 0x0C))/4) - 2, 2, "");
								}
								break;

							case 0x80000016ul:
								if ((zData2[0].dword[0] != 0xFFFFFFFFul) &&
									((zData2[0].dword[0] & 0x80000000ul) == 0)) {
									fseek(tlbfile, FileSectionMapping[SNE_STRING_TABLE].address +
													zData2[0].dword[0], SEEK_SET);
									if (!ReadData(&zData3, 1, tlbfile)) return;
									nTemp = zData3[0].word[0];
									fseek(tlbfile, FileSectionMapping[SNE_STRING_TABLE].address +
													zData2[0].dword[0] + 2, SEEK_SET);
									if (!ReadData(&zData3, (nTemp+5)/4, tlbfile)) return;

									pTempString = (char *)malloc(nTemp+1);
									if (pTempString == NULL) {
										fprintf(stderr, "*** Error: Out of Memory or Memory Allocation Error!\n\n");
										fclose(tlbfile);
										return;
									}
									strncpy(pTempString, (const char*)zData3, nTemp);
									pTempString[nTemp] = 0;

									WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 0, ": HelpString : String Table Offset = 0x%04lX = \"%s\"",
																	zData2[0].dword[0], pTempString);
								} else {
									if (zData2[0].dword[0] == 0xFFFFFFFFul) {
										WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 0, ": HelpString : String Table Offset = -1 = <NONE>");
									} else {
										WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 0, ": ??? = 0x%04lX (%ld)",
																	zData2[1].dword[0], zData2[1].dword[0]);
									}
								}

								if (pTempString) {
									free(pTempString);
									pTempString = NULL;
								}

								if (((nEntrySize - 0x18 - (nSubItemCount * 0x0C))/4) >= 2) {
									WriteFormattedData(OME_DWORDS, &nAddr, zData2, ((nEntrySize - 0x18 - (nSubItemCount * 0x0C))/4) - 1, 1, "");
								}
								break;

							default:
								WriteFormattedData(OME_DWORDS, &nAddr, zData2, ((nEntrySize - 0x18 - (nSubItemCount * 0x0C))/4), 0, "");
								break;
						}

						fseek(tlbfile, nSeekSave, SEEK_SET);
					}

					for (i=0; (DWORD)i<nSubItemCount; i++) {
						if (!ReadData(&zData2, 3, tlbfile)) return;

						nSeekSave = ftell(tlbfile);

						printf("\nArgument %ld:\n", i+1);
						WriteSectionBreak('-', 20, "");

						pTemp = DecodeTypeCode(zData2[0].dword[0], tlbfile);
						WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 0, ": Type Code: 0x%08lX = %s", zData2[0].dword[0], ((pTemp != NULL) ? pTemp : "???"));
						if (pTemp) free(pTemp);

						if (zData2[1].dword[0] != 0xFFFFFFFFul) {
							fseek(tlbfile, FileSectionMapping[SNE_TYPE_NAMES_TABLE].address +
												zData2[1].dword[0], SEEK_SET);
							if (!ReadData(&zData3, 3, tlbfile)) return;
							nTemp = zData3[2].byte[0];
							if (!ReadData(&zData3, (nTemp+3)/4, tlbfile)) return;

							pTempString = (char *)malloc(nTemp+1);
							if (pTempString == NULL) {
								fprintf(stderr, "*** Error: Out of Memory or Memory Allocation Error!\n\n");
								fclose(tlbfile);
								return;
							}
							strncpy(pTempString, (const char*)zData3, nTemp);
							pTempString[nTemp] = 0;

							WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 1, ": Type Names Table Offset = 0x%04lX = \"%s\"",
															zData2[1].dword[0], pTempString);
						} else {
							WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 1, ": Type Names Table Offset = -1 = retval");
						}

						if (pTempString) {
							free(pTempString);
							pTempString = NULL;
						}

						WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 2, ": ??? = 0x%04lX (%ld)",
															zData2[2].dword[0], zData2[2].dword[0]);

						fseek(tlbfile, nSeekSave, SEEK_SET);
					}
					if (nSubItemCount) printf("\n");

					printf("\n");
				}

				printf("Object Entry Table:\n");
				WriteSectionBreak('-', 20, "");

				for (i=0; (DWORD)i<nItemCount; i++) {
					if (!ReadData(&zData, 1, tlbfile)) return;

					nSeekSave = ftell(tlbfile);

					if (ObjectDataEntries[i].ofs_typename != 0xFFFFFFFFul) {
						fseek(tlbfile, FileSectionMapping[SNE_TYPE_NAMES_TABLE].address +
													ObjectDataEntries[i].ofs_typename, SEEK_SET);
						if (!ReadData(&zData3, 3, tlbfile)) return;
						nTemp = zData3[2].byte[0];
						if (!ReadData(&zData3, (nTemp+3)/4, tlbfile)) return;

						pTempString = (char *)malloc(nTemp+1);
						if (pTempString == NULL) {
							fprintf(stderr, "*** Error: Out of Memory or Memory Allocation Error!\n\n");
							fclose(tlbfile);
							return;
						}
						strncpy(pTempString, (const char*)zData3, nTemp);
						pTempString[nTemp] = 0;
					}

					fseek(tlbfile, nSeekSave, SEEK_SET);

					WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 0, ": id(0x%08lX)%s%s", zData[0].dword[0],
												((pTempString != NULL) ? " = " : ""),
												((pTempString != NULL) ? pTempString : ""));

					if (pTempString) {
						free(pTempString);
						pTempString = NULL;
					}
				}
				printf("\n");

				for (i=0; (DWORD)i<nItemCount; i++) {
					if (!ReadData(&zData, 1, tlbfile)) return;

					nSeekSave = ftell(tlbfile);

					if (ObjectDataEntries[i].ofs_typename != 0xFFFFFFFFul) {
						fseek(tlbfile, FileSectionMapping[SNE_TYPE_NAMES_TABLE].address +
													ObjectDataEntries[i].ofs_typename, SEEK_SET);
						if (!ReadData(&zData3, 3, tlbfile)) return;
						nTemp = zData3[2].byte[0];
						if (!ReadData(&zData3, (nTemp+3)/4, tlbfile)) return;

						pTempString = (char *)malloc(nTemp+1);
						if (pTempString == NULL) {
							fprintf(stderr, "*** Error: Out of Memory or Memory Allocation Error!\n\n");
							fclose(tlbfile);
							return;
						}
						strncpy(pTempString, (const char*)zData3, nTemp);
						pTempString[nTemp] = 0;
					}

					fseek(tlbfile, nSeekSave, SEEK_SET);

					WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 0, ": Type Names Table Offset = 0x%04lX%s%s%s", zData[0].dword[0],
													((pTempString != NULL) ? " = \"" : ""),
													((pTempString != NULL) ? pTempString : ""),
													((pTempString != NULL) ? "\"" : ""));

					if (pTempString) {
						free(pTempString);
						pTempString = NULL;
					}
				}
				printf("\n");

				for (i=0; (DWORD)i<nItemCount; i++) {
					if (!ReadData(&zData, 1, tlbfile)) return;

					nSeekSave = ftell(tlbfile);

					if (ObjectDataEntries[i].ofs_typename != 0xFFFFFFFFul) {
						fseek(tlbfile, FileSectionMapping[SNE_TYPE_NAMES_TABLE].address +
													ObjectDataEntries[i].ofs_typename, SEEK_SET);
						if (!ReadData(&zData3, 3, tlbfile)) return;
						nTemp = zData3[2].byte[0];
						if (!ReadData(&zData3, (nTemp+3)/4, tlbfile)) return;

						pTempString = (char *)malloc(nTemp+1);
						if (pTempString == NULL) {
							fprintf(stderr, "*** Error: Out of Memory or Memory Allocation Error!\n\n");
							fclose(tlbfile);
							return;
						}
						strncpy(pTempString, (const char*)zData3, nTemp);
						pTempString[nTemp] = 0;
					}

					fseek(tlbfile, nSeekSave, SEEK_SET);

					WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 0, ": Offset into Info Above = 0x%04lX%s%s%s", zData[0].dword[0],
													((pTempString != NULL) ? " (" : ""),
													((pTempString != NULL) ? pTempString : ""),
													((pTempString != NULL) ? ")" : ""));

					if (pTempString) {
						free(pTempString);
						pTempString = NULL;
					}
				}
				printf("\n");
			}
		}
	}

	fclose(tlbfile);
}

int main(int argc, char* argv[])
{
	fprintf(stderr, "Dump Type Library Utility v%d.%02d\n", (VERSION/100), (VERSION%100));
	fprintf(stderr, "Copyright(c)2002 Dewtronics/Donald Whisnant\n\n");

	if (argc != 2) {
		fprintf(stderr, "Usage:  dumptlb <tlb-filename>\n\n");
		fprintf(stderr, "    Where:  <tlb-filename> is the pathname to a Microsoft TLB file\n\n");
		fprintf(stderr, "    Output is sent to stdout\n\n");
		return -1;
	}

	WriteHeader(argv[1]);
	DumpTLB(argv[1]);

	// Handle Cleanup:
	if (zData) free(zData);
	if (zData2) free(zData2);
	if (zData3) free(zData3);
	if (ObjectIndexes) free(ObjectIndexes);
	if (ObjectDataMapping) free(ObjectDataMapping);
	if (ObjectDataEntries) free(ObjectDataEntries);
	if (pTempString) free(pTempString);

	return 0;
}

