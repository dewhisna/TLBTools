// DumpTLB.cpp : Defines the entry point for the console application.
//
//

#include "stdafx.h"

#define VERSION 201

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
					"Constants Table",
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
				SNE_CONSTANTS_TABLE = 11,
				SNE_WEIRD_GUID_REF_TABLE = 12
} SECTION_NAMES_ENUM;

//typedef enum {	OTC_UNKNOWN = 0,
//				OTC_ENUM = 0x2120,
//				OTC_STRUCT = 0x2121,
//				OTC_MODULE = 0x0922,
//				OTC_DISPINTERFACE = 0x2124,
//				OTC_COCLASS = 0x2125,
//				OTC_ALIAS = 0x2126,
//				OTC_INTERFACE = 0x2134
//} OBJECT_TYPE_CODES_ENUM;

typedef enum {	OTC_UNKNOWN = 0,
				OTC_ENUM = 0x20,
				OTC_STRUCT = 0x21,
				OTC_MODULE = 0x22,
				OTC_DISPINTERFACE = 0x24,
				OTC_COCLASS = 0x25,
				OTC_ALIAS = 0x26,
				OTC_INTERFACE = 0x34
} OBJECT_TYPE_CODES_ENUM;

typedef struct {
	DWORD	address;
	DWORD	length;
	DWORD	unknown1;
	DWORD	unknown2;
} FILE_SECTION_MAPPING_TABLE_ENTRY_STRUCT;

typedef struct {
	OBJECT_TYPE_CODES_ENUM	nType;
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
	BOOL	b_ismethod;
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

//	Prototypes:
extern char *DecodeTypeNameEntry(DWORD nTypeNameOffset, FILE *zFile);

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

	if ((szLabel != NULL) && (strlen(szLabel) != 0)) {
		nTemp = (nWidth - strlen(szLabel) - 2) / 2;
	} else {
		nTemp = nWidth / 2;
	}
	sprintf(szSep, "%c", zSep);

	if ((szLabel != NULL) && (strlen(szLabel) != 0)) printf("\n");
	PrintRepString(szSep, nTemp);
	if ((szLabel != NULL) && (strlen(szLabel) != 0)) printf(" %s ", szLabel);
	PrintRepString(szSep, nTemp);
	if ((szLabel != NULL) && 
		(((nTemp * 2) + strlen(szLabel) + ((strlen(szLabel) != 0) ? 2 : 0)) != nWidth)) printf(szSep);
	printf("\n");
	if ((szLabel != NULL) && (strlen(szLabel) != 0)) printf("\n");
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

char *DecodeObjectType(WORD nTypeCode)
{
	char *pType = "???";

	switch (nTypeCode & 0xFF) {
		case OTC_ENUM:
			pType = "ENUM";
			break;
		case OTC_STRUCT:
			pType = "STRUCT";
			break;
		case OTC_MODULE:
			pType = "MODULE";
			break;
		case OTC_DISPINTERFACE:
			pType = "DISPINTERFACE";
			break;
		case OTC_COCLASS:
			pType = "COCLASS";
			break;
		case OTC_ALIAS:
			pType = "ALIAS";
			break;
		case OTC_INTERFACE:
			pType = "INTERFACE";
			break;
	}

	return strdup(pType);
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
		pTemp = DecodeTypeNameEntry(ObjectDataMapping[nTemp].ofs_typename, zFile);
		if (pTemp) {
			strcpy(Buffer, pTemp);
			free(pTemp);
		}
		pTemp = NULL;

		nLocalOffset = FileSectionMapping[SNE_GUID_TABLE].length;	// Set this to skip next loop
	}

	pTemp = NULL;
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

char *DecodeStringEntry(DWORD nStringOffset, FILE *zFile)
{
	DWORD nSeekSave;
	DATABUF_UNION *myData = NULL;
	char *pTemp = NULL;
	int nTemp;

	if (nStringOffset == 0xFFFFFFFFul) return NULL;

	nSeekSave = ftell(zFile);

	while (1) {
		fseek(zFile, FileSectionMapping[SNE_STRING_TABLE].address + nStringOffset, SEEK_SET);
		if (!ReadData(&myData, 1, zFile)) break;

		nTemp = myData[0].word[0];
		fseek(zFile, FileSectionMapping[SNE_STRING_TABLE].address + nStringOffset + 2, SEEK_SET);
		if (!ReadData(&myData, (nTemp+5)/4, zFile)) break;

		pTemp = (char *)malloc(nTemp+1);
		if (pTemp == NULL) {
			fprintf(stderr, "*** Error: Out of Memory or Memory Allocation Error!\n\n");
			break;
		}
		strncpy(pTemp, (const char*)myData, nTemp);
		pTemp[nTemp] = 0;
		break;
	}

	fseek(zFile, nSeekSave, SEEK_SET);

	if (myData) free(myData);

	return pTemp;
}

char *DecodeTypeNameEntry(DWORD nTypeNameOffset, FILE *zFile)
{
	DWORD nSeekSave;
	DATABUF_UNION *myData = NULL;
	char *pTemp = NULL;
	int nTemp;

	if (nTypeNameOffset == 0xFFFFFFFFul) return NULL;

	nSeekSave = ftell(zFile);

	while (1) {
		fseek(zFile, FileSectionMapping[SNE_TYPE_NAMES_TABLE].address + nTypeNameOffset, SEEK_SET);
		if (!ReadData(&myData, 3, zFile)) break;

		nTemp = myData[2].byte[0];
		if (!ReadData(&myData, (nTemp+3)/4, zFile)) break;

		pTemp = (char *)malloc(nTemp+1);
		if (pTemp == NULL) {
			fprintf(stderr, "*** Error: Out of Memory or Memory Allocation Error!\n\n");
			break;
		}
		strncpy(pTemp, (const char*)myData, nTemp);
		pTemp[nTemp] = 0;
		break;
	}

	fseek(zFile, nSeekSave, SEEK_SET);

	if (myData) free(myData);

	return pTemp;
}

char *LookupInheritedInterface(DWORD nExposedInterfaceOffset, FILE *zFile)
{
	DWORD nSeekSave;
	DATABUF_UNION *myData = NULL;
	char *pTemp = NULL;

	if (nExposedInterfaceOffset == 0xFFFFFFFFul) return NULL;
	if (nExposedInterfaceOffset == 0xFFFFFFFEul) return strdup("ThisTypeLib");
	if (nExposedInterfaceOffset == 0x1ul) return strdup("IDispatch");

	nSeekSave = ftell(zFile);

	fseek(zFile, FileSectionMapping[SNE_EXPOSED_INTERFACES_TABLE].address + nExposedInterfaceOffset, SEEK_SET);
	if (ReadData(&myData, 1, zFile)) pTemp = DecodeObject(myData[0].dword[0], zFile, 0);
	fseek(zFile, nSeekSave, SEEK_SET);

	if (myData) free(myData);

	return pTemp;
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
				if ((nTypeCode>>16) == 0xFFFE) {
					strcpy(Buffer, "const");
				} else {
					pTemp = DecodeVariantTypeCode((nTypeCode>>16) & 0x00007FFF);
					if (pTemp != NULL) {
						strcpy(Buffer, pTemp);
						free(pTemp);
					}
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

char *DecodeObjectFlags(DWORD nObjectFlags)
{
	char Buffer[1024];
	char *pAdd;
	int nCount;
	int nBit;
	int nMask;

	if (nObjectFlags == 0) return strdup("noncreatable");

	Buffer[0]=0;

	nCount = 0;
	for (nBit=0; nBit<31; nBit++) {
		nMask = (1 << nBit);
		pAdd = NULL;

		if (nMask & nObjectFlags) {
			switch (nBit) {
				case 0:
					pAdd = "appobject";
					break;
				case 1:
					pAdd = "creatable";
					break;
				case 2:
					pAdd = "licensed";
					break;
				case 3:
					pAdd = "predeclid";
					break;
				case 4:
					pAdd = "hidden";
					break;
				case 5:
					pAdd = "control";
					break;
				case 6:
					pAdd = "dual";
					break;
				case 7:
					pAdd = "nonextensible";
					break;
				case 8:
					pAdd = "oleautomation";
					break;
				case 9:
					pAdd = "restricted";
					break;
				case 10:
					pAdd = "aggregatable";
					break;
				case 11:
					pAdd = "replaceable";
					break;
				case 12:
					pAdd = "dispatchable";
					break;
				case 13:
					pAdd = "reversebind";
					break;
				default:
					pAdd = "???";
					break;
			}
		}

		if (pAdd != NULL) {
			if (nCount) strcat(Buffer, ", ");
			strcat(Buffer, pAdd);
			nCount++;
		}
	}

	return strdup(Buffer);
}

char *DecodeArgumentType(DWORD nTypeCode)
{
	char Buffer[1024];
	char *pAdd;
	int nCount;
	int nBit;
	int nMask;

	Buffer[0]=0;

	strcat(Buffer, "[");

	nCount = 0;
	for (nBit=0; nBit<31; nBit++) {
		nMask = (1 << nBit);
		pAdd = NULL;

		if (nMask & nTypeCode) {
			switch (nBit) {
				case 0:
					pAdd = "in";
					break;
				case 1:
					pAdd = "out";
					break;
				case 2:
					pAdd = "lcid";
					break;
				case 3:
					pAdd = "retval";
					break;
				case 4:
					pAdd = "optional";
					break;
				case 5:
					pAdd = "default(?)";
					break;
				case 6:
					pAdd = "custom(?)";
					break;
				default:
					pAdd = "???";
					break;
			}
		}

		if (pAdd != NULL) {
			if (nCount) strcat(Buffer, ", ");
			strcat(Buffer, pAdd);
			nCount++;
		}
	}

	strcat(Buffer, "]");

	return strdup(Buffer);
}

char *DecodeInterfaceFlags(DWORD nInterfaceFlags)
{
	char Buffer[1024];
	char *pAdd;
	int nCount;
	int nBit;
	int nMask;

	Buffer[0]=0;

	strcat(Buffer, "[");

	nCount = 0;
	for (nBit=0; nBit<31; nBit++) {
		nMask = (1 << nBit);
		pAdd = NULL;

		if (nMask & nInterfaceFlags) {
			switch (nBit) {
				case 0:
					pAdd = "default";
					break;
				case 1:
					pAdd = "source";
					break;
				default:
					pAdd = "???";
					break;
			}
		}

		if (pAdd != NULL) {
			if (nCount) strcat(Buffer, ", ");
			strcat(Buffer, pAdd);
			nCount++;
		}
	}

	strcat(Buffer, "]");

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
	float nSingleTemp;
	double nDoubleTemp;
	__int64 nI64Temp;
	int nPos;

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
	WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 0, ": Object Count = %ld\n", zData[0].dword[0]);
	nObjectCount = zData[0].dword[0];

	if (!ReadData(&zData, 12, tlbfile)) return;
	if (zData[0].dword[0] != 0xFFFFFFFFul) {
		WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 0, ": Library Help String - Offset = 0x%04lX", zData[0].dword[0]);
	} else {
		WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 0, ": Library Help String = -1 = <None>");
	}
	WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 1, ": ??? = 0x%04lX = %ld", zData[1].dword[0], zData[1].dword[0]);
	WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 2, ": Help Context = 0x%08lX", zData[2].dword[0]);
	WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 3, ": ??? = 0x%04lX = %ld", zData[3].dword[0], zData[3].dword[0]);
	WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 4, ": ??? = 0x%04lX = %ld", zData[4].dword[0], zData[4].dword[0]);
	WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 5, ": ??? = 0x%04lX = %ld", zData[5].dword[0], zData[5].dword[0]);
	if (zData[6].dword[0] != 0xFFFFFFFFul) {
		WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 6, ": Help Filename String - Offset = 0x%04lX", zData[6].dword[0]);
	} else {
		WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 6, ": Help Filename String = -1 = <None>");
	}
	for (i=7; i<12; i++) {
		WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, i, ": ??? = 0x%04lX", zData[i].dword[0]);
	}

	if (zData[1].dword[0] & 0x4000ul) {
		// It appears that either bit 0x4000 of offset 0x0028 determines whether or not we have the
		//		following extra word.  But, it could also be the extra 0x0100 at offset 0x0014.  But,
		//		it is going to take more sample files to know for sure.
		if (!ReadData(&zData, 1, tlbfile)) return;
		WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 0, ": ??? = 0x%04lX", zData[0].dword[0]);
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
		ObjectDataMapping[i].nType = OTC_UNKNOWN;
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
		ObjectDataMapping[i].nType = (OBJECT_TYPE_CODES_ENUM)zData[0].word[0];
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

						pTempString = DecodeTypeNameEntry(zData[13].dword[0], tlbfile);
						if (pTempString == NULL) pTempString = strdup("???");

						printf("Offset %ld : %s\n", (nAddr - FileSectionMapping[nCurSection].address), pTempString);
						WriteSectionBreak('-', 40, "");

						pTemp = DecodeObjectType(zData[0].word[0]);
						WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 0, "    : Type Code = 0x%04X - %s",
														zData[0].word[0],
														((pTemp != NULL) ? pTemp : "???"));
						if (pTemp) free(pTemp);
						WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 1, "    : Item Index = %d", zData[0].word[1]);
						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 1, ": Address = 0x%04lX", zData[1].dword[0]);
						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 2, ": ??? = 0x%04lX", zData[2].dword[0]);
						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 3, ": ??? = 0x%04lX", zData[3].dword[0]);
						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 4, ": ??? = 0x%04lX", zData[4].dword[0]);
						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 5, ": ??? = 0x%04lX", zData[5].dword[0]);
						WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 12, "    : Method Item Count = %d", zData[6].word[0]);
						WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 13, "    : TypeDef Item Count = %d", zData[6].word[1]);

						for (i=7; i<11; i++) {
							WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, i, ": ??? = 0x%04lX", zData[i].dword[0]);
						}

						if (zData[11].dword[0] != 0xFFFFFFFFul) {
							pTemp = DecodeGUID(zData[11].dword[0], tlbfile);

							WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 11, ": GUID Table Offset = 0x%04lX = %s",
												zData[11].dword[0],
												((pTemp != NULL) ? pTemp : "???"));
							if (pTemp) free(pTemp);
						} else {
							WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 11, ": GUID Table Offset = -1 = <NONE>");
						}

						pTemp = DecodeObjectFlags(zData[12].dword[0]);
						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 12, ": Object Flags = 0x%04lX = %s",
												zData[12].dword[0], ((pTemp != NULL) ? pTemp : "<ERROR>"));
						if (pTemp) free(pTemp);

						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 13, ": Type Names Table Offset = 0x%04lX = \"%s\"",
											zData[13].dword[0], pTempString);
						if (pTempString) {
							free(pTempString);
							pTempString = NULL;
						}

						WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 28, "    : Version Major = %d", zData[14].word[0]);
						WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 29, "    : Version Minor = %d", zData[14].word[1]);

						if (zData[15].dword[0] != 0xFFFFFFFFul) {
							pTempString = DecodeStringEntry(zData[15].dword[0], tlbfile);

							WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 15, ": HelpString : String Table Offset = 0x%04lX = \"%s\"",
															zData[15].dword[0], ((pTempString != NULL) ? pTempString : "<ERROR-INVALID>"));
						} else {
							WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 15, ": HelpString : String Table Offset = -1 = <NONE>");
						}
						if (pTempString) {
							free(pTempString);
							pTempString = NULL;
						}

						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 16, ": ??? = 0x%08lX (%ld)",
															zData[16].dword[0], zData[16].dword[0]);

						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 17, ": Help Context = 0x%08lX", zData[17].dword[0]);
						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 18, ": ??? = 0x%04lX", zData[18].dword[0]);

						for (i=38; i<42; i++) {
							WriteFormattedData(OME_WORDS, &nAddr, zData, 1, i, "    : ??? = 0x%04lX (%ld)",
															zData[i/2].word[i%2], zData[i/2].word[i%2]);
						}

						if (zData[21].dword[0] != 0xFFFFFFFFul) {
							pTempString = LookupInheritedInterface(zData[21].dword[0], tlbfile);
							WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 21, ": Inherited from = 0x%04lX = \"%s\"",
															zData[21].dword[0], ((pTempString != NULL) ? pTempString : "???"));
						} else {
							WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 21, ": Inherited from = -1 = <Not Inherited>");
						}
						if (pTempString) {
							free(pTempString);
							pTempString = NULL;
						}

						for (i=44; i<48; i++) {
							WriteFormattedData(OME_WORDS, &nAddr, zData, 1, i, "    : ??? = 0x%04lX (%ld)",
															zData[i/2].word[i%2], zData[i/2].word[i%2]);
						}

						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 24, ": ??? = 0x%04lX", zData[24].dword[0]);
						printf("\n");
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
						printf("GUID: 0x%04lX:\n", (nAddr - FileSectionMapping[SNE_GUID_TABLE].address));
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
						printf("Interface: 0x%04lX:\n", (nAddr - FileSectionMapping[SNE_EXPOSED_INTERFACES_TABLE].address));
						WriteSectionBreak('-', 40, "");

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

						pTempString = DecodeInterfaceFlags(zData[1].dword[0]);

						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 1, ": 0x%04lX = %s",
											zData[1].dword[0], ((pTempString != NULL) ? pTempString : "???"));

						if (pTempString) {
							free(pTempString);
							pTempString = NULL;
						}

						WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 2, ": ??? = 0x%04lX", zData[2].dword[0]);

						if (zData[3].dword[0] != 0xFFFFFFFFul) {
							pTempString = LookupInheritedInterface(zData[3].dword[0], tlbfile);

							WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 3, ": Next Interface = 0x%04lX = \"%s\"",
													zData[3].dword[0], ((pTempString != NULL) ? pTempString : "???"));
						} else {
							WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 3, ": Next Interface = -1 = <None>");
						}

						if (pTempString) {
							free(pTempString);
							pTempString = NULL;
						}

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

						if (zData[0].dword[0] != 0xFFFFFFFFul) {

							if (pTempString) {
								free(pTempString);
								pTempString = NULL;
							}

							pTempString = DecodeTypeNameEntry(zData[0].dword[0], tlbfile);
							if (pTempString == NULL) pTempString = strdup("???");

							WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 0, ": Type Names Table Offset = 0x%04lX = \"%s\"",
												zData[0].dword[0], pTempString);
						} else {
							WriteFormattedData(OME_DWORDS, &nAddr, zData, 1, 0, "");
						}

						if (pTempString) {
							free(pTempString);
							pTempString = NULL;
						}
						break;

					case SNE_TYPE_NAMES_TABLE:
						printf("Type Name: 0x%08lX:\n", (nAddr - FileSectionMapping[SNE_TYPE_NAMES_TABLE].address));
						WriteSectionBreak('-', 40, "");

						if (!ReadData(&zData, 3, tlbfile)) return;

						if (zData[0].dword[0] != 0xFFFFFFFFul) {
							nTemp = -1;
							for (i=0; ((i<(int)nObjectCount) && (nTemp == -1)); i++)
								 if (ObjectIndexes[i] == zData[0].dword[0]) nTemp = i;

							if (pTempString) {
								free(pTempString);
								pTempString = NULL;
							}

							pTempString = DecodeTypeNameEntry(ObjectDataMapping[nTemp].ofs_typename, tlbfile);

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

					case SNE_CONSTANTS_TABLE:
						printf("Offset 0x%04lX:\n", (nAddr - FileSectionMapping[SNE_CONSTANTS_TABLE].address));
						WriteSectionBreak('-', 40, "");

						nSeekSave = ftell(tlbfile);

						if (!ReadData(&zData, 1, tlbfile)) return;

						pTemp = DecodeVariantTypeCode(zData[0].word[0]);
						WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 0, "    : Type Identifier = 0x%04X%s%s",
															zData[0].word[0],
															((pTemp != NULL) ? " = " : ""),
															((pTemp != NULL) ? pTemp : ""));
						if (pTemp) free(pTemp);

						nPos = 2;
						switch (zData[0].word[0] & 0xFFFul) {
							case 0x0000:		// EMPTY
								break;
	
							case 0x0001:		// NULL
								break;
	
							case 0x0002:		// short
								WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 1, "    : Value = 0x%04X (%d)",
															zData[0].word[1], zData[0].word[1]);
								nPos += 2;
								break;
	
							case 0x0003:		// long
								fseek(tlbfile, nSeekSave, SEEK_SET);
								if (!ReadData(&zData, 2, tlbfile)) return;

								nTemp = (int)*((DWORD *)&zData[0].word[1]);

								WriteFormattedData(OME_DWORDS, &nAddr, (DATABUF_UNION*)&zData[0].word[1], 1, 0,
															": Value = 0x%08lX (%ld)", nTemp, nTemp);
								nPos += 4;
								break;
	
							case 0x0004:		// single
								fseek(tlbfile, nSeekSave, SEEK_SET);
								if (!ReadData(&zData, 2, tlbfile)) return;

								nSingleTemp = *((float *)&zData[0].word[1]);
								WriteFormattedData(OME_DWORDS, &nAddr, (DATABUF_UNION*)&zData[0].word[1], 1, 0,
															": Value = %f", nSingleTemp);
								nPos += 4;
								break;
	
							case 0x0005:		// double
								fseek(tlbfile, nSeekSave, SEEK_SET);
								if (!ReadData(&zData, 3, tlbfile)) return;

								nDoubleTemp = *((double *)&zData[0].word[1]);
								WriteFormattedData(OME_DWORDS, &nAddr, (DATABUF_UNION*)&zData[0].word[1], 2, 0,
															": Value = %f", nDoubleTemp);

								nPos += 8;
								break;

							case 0x0006:		// CURRENCY
								fseek(tlbfile, nSeekSave, SEEK_SET);
								if (!ReadData(&zData, 3, tlbfile)) return;

								WriteFormattedData(OME_DWORDS, &nAddr, (DATABUF_UNION*)&zData[0].word[1], 2, 0,
															": Value = 0x%08lX%08lX",
															((DATABUF_UNION*)&zData[0].word[1])->dword[0],
															((DATABUF_UNION*)&zData[1].word[1])->dword[0]);
								nPos += 8;
								break;

							case 0x0007:		// DATE
								fseek(tlbfile, nSeekSave, SEEK_SET);
								if (!ReadData(&zData, 3, tlbfile)) return;

								WriteFormattedData(OME_DWORDS, &nAddr, (DATABUF_UNION*)&zData[0].word[1], 2, 0,
															": Value = 0x%08lX%08lX",
															((DATABUF_UNION*)&zData[0].word[1])->dword[0],
															((DATABUF_UNION*)&zData[1].word[1])->dword[0]);
								nPos += 8;
								break;

							case 0x0008:		// BSTR
								fseek(tlbfile, nSeekSave, SEEK_SET);
								if (!ReadData(&zData, 2, tlbfile)) return;

								nTemp = (int)*((DWORD *)&zData[0].word[1]);

								WriteFormattedData(OME_DWORDS, &nAddr, (DATABUF_UNION*)&zData[0].word[1], 1, 0,
															": Length = %ld", nTemp);

								fseek(tlbfile, nSeekSave, SEEK_SET);
								if (!ReadData(&zData, (nTemp+6)/4, tlbfile)) return;

								WriteFormattedText(&nAddr, zData, nTemp, 6, "Value");

								nPos += 4 + nTemp;
								break;

							case 0x0009:		// IDispatch
								fseek(tlbfile, nSeekSave, SEEK_SET);
								if (!ReadData(&zData, 2, tlbfile)) return;

								nTemp = (int)*((DWORD *)&zData[0].word[1]);

								WriteFormattedData(OME_DWORDS, &nAddr, (DATABUF_UNION*)&zData[0].word[1], 1, 0,
															": Value = 0x%08lX (%ld)", nTemp, nTemp);
								nPos += 4;
								break;

							case 0x000A:		// SCODE
								fseek(tlbfile, nSeekSave, SEEK_SET);
								if (!ReadData(&zData, 2, tlbfile)) return;

								nTemp = (int)*((DWORD *)&zData[0].word[1]);

								WriteFormattedData(OME_DWORDS, &nAddr, (DATABUF_UNION*)&zData[0].word[1], 1, 0,
															": Value = 0x%08lX (%ld)", nTemp, nTemp);
								nPos += 4;
								break;

							case 0x000B:		// VARIANT_BOOL
								WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 1,
															": Value = %s", ((zData[0].word[1] == VARIANT_FALSE) ? "FALSE" : "TRUE"));
								nPos += 2;
								break;

							case 0x000C:		// VARIANT
								// DON'T CURRENTLY KNOW HOW TO HANDLE VARIANTS!
								ASSERT(FALSE);
								break;

							case 0x000D:		// IUnknown
								fseek(tlbfile, nSeekSave, SEEK_SET);
								if (!ReadData(&zData, 2, tlbfile)) return;

								nTemp = (int)*((DWORD *)&zData[0].word[1]);

								WriteFormattedData(OME_DWORDS, &nAddr, (DATABUF_UNION*)&zData[0].word[1], 1, 0,
															": Value = 0x%08lX (%ld)", nTemp, nTemp);
								nPos += 4;
								break;

							case 0x000E:		// decimal
								fseek(tlbfile, nSeekSave, SEEK_SET);
								if (!ReadData(&zData, 4, tlbfile)) return;

								WriteFormattedData(OME_BYTES, &nAddr, zData, 14, 2,
															": Decimal Value");

								nPos += 14;
								break;

							case 0x0010:		// char
								WriteFormattedData(OME_BYTES, &nAddr, zData, 1, 2, "    : Value = 0x%02X (%d) '%c'",
															zData[0].byte[2], zData[0].byte[2], zData[0].byte[2]);
								nPos += 1;
								break;

							case 0x0011:		// unsigned char
								WriteFormattedData(OME_BYTES, &nAddr, zData, 1, 2, "    : Value = 0x%02X (%u) '%c'",
															zData[0].byte[2], zData[0].byte[2], zData[0].byte[2]);
								nPos += 1;
								break;

							case 0x0012:		// unsigned short
								WriteFormattedData(OME_WORDS, &nAddr, zData, 1, 1, "    : Value = 0x%04X (%u)",
															zData[0].word[1], zData[0].word[1]);
								nPos += 2;
								break;

							case 0x0013:		// unsigned long
								fseek(tlbfile, nSeekSave, SEEK_SET);
								if (!ReadData(&zData, 2, tlbfile)) return;

								nTemp = (int)*((DWORD *)&zData[0].word[1]);

								WriteFormattedData(OME_DWORDS, &nAddr, (DATABUF_UNION*)&zData[0].word[1], 1, 0,
															": Value = 0x%08lX (%lu)", nTemp, nTemp);
								nPos += 4;
								break;

							case 0x0014:		// __int64
								fseek(tlbfile, nSeekSave, SEEK_SET);
								if (!ReadData(&zData, 3, tlbfile)) return;

								nI64Temp = *((__int64 *)&zData[0].word[1]);

								WriteFormattedData(OME_DWORDS, &nAddr, (DATABUF_UNION*)&zData[0].word[1], 2, 0,
															": Value = 0x%08I64X (%I64d)", nI64Temp, nI64Temp);
								nPos += 8;
								break;

							case 0x0015:		// unsigned __int64
								fseek(tlbfile, nSeekSave, SEEK_SET);
								if (!ReadData(&zData, 3, tlbfile)) return;

								nI64Temp = *((__int64 *)&zData[0].word[1]);

								WriteFormattedData(OME_DWORDS, &nAddr, (DATABUF_UNION*)&zData[0].word[1], 2, 0,
															": Value = 0x%08I64X (%I64u)", nI64Temp, nI64Temp);
								nPos += 8;
								break;

							case 0x0016:		// int
								fseek(tlbfile, nSeekSave, SEEK_SET);
								if (!ReadData(&zData, 2, tlbfile)) return;

								nTemp = (int)*((DWORD *)&zData[0].word[1]);

								WriteFormattedData(OME_DWORDS, &nAddr, (DATABUF_UNION*)&zData[0].word[1], 1, 0,
															": Value = 0x%08lX (%ld)", nTemp, nTemp);
								nPos += 4;
								break;

							case 0x0017:		// unsigned int
								fseek(tlbfile, nSeekSave, SEEK_SET);
								if (!ReadData(&zData, 2, tlbfile)) return;

								nTemp = (int)*((DWORD *)&zData[0].word[1]);

								WriteFormattedData(OME_DWORDS, &nAddr, (DATABUF_UNION*)&zData[0].word[1], 1, 0,
															": Value = 0x%08lX (%lu)", nTemp, nTemp);
								nPos += 4;
								break;

							case 0x0018:		// void
								break;

							case 0x0019:		// HRESULT
								fseek(tlbfile, nSeekSave, SEEK_SET);
								if (!ReadData(&zData, 2, tlbfile)) return;

								nTemp = (int)*((DWORD *)&zData[0].word[1]);

								WriteFormattedData(OME_DWORDS, &nAddr, (DATABUF_UNION*)&zData[0].word[1], 1, 0,
															": Value = 0x%08lX (%ld)", nTemp, nTemp);
								nPos += 4;
								break;

							case 0x001A:		// VT_PTR
								fseek(tlbfile, nSeekSave, SEEK_SET);
								if (!ReadData(&zData, 2, tlbfile)) return;

								nTemp = (int)*((DWORD *)&zData[0].word[1]);

								WriteFormattedData(OME_DWORDS, &nAddr, (DATABUF_UNION*)&zData[0].word[1], 1, 0,
															": Value = 0x%08lX (%ld)", nTemp, nTemp);
								nPos += 4;
								break;

							case 0x001B:		// VT_SAFEARRAY
								// DON'T CURRENTLY KNOW HOW TO HANDLE SAFEARRAY!
								ASSERT(FALSE);
								break;

							case 0x001C:		// VT_CARRAY
								// DON'T CURRENTLY KNOW HOW TO HANDLE CARRAY!
								ASSERT(FALSE);
								break;

							case 0x001D:		// VT_USERDEFINED
								// DON'T CURRENTLY KNOW HOW TO HANDLE USERDEFINED!
								ASSERT(FALSE);
								break;

							case 0x001E:		// LPSTR
								// DON'T CURRENTLY KNOW HOW TO HANDLE LPSTR!
								ASSERT(FALSE);
								break;

							case 0x001F:		// LPWSTR
								// DON'T CURRENTLY KNOW HOW TO HANDLE LPWSTR!
								ASSERT(FALSE);
								break;

							case 0x0040:		// FILETIME
								// DON'T CURRENTLY KNOW HOW TO HANDLE FILETIME!
								ASSERT(FALSE);
								break;

							case 0x0041:		// BLOB
								// DON'T CURRENTLY KNOW HOW TO HANDLE BLOB!
								ASSERT(FALSE);
								break;

							case 0x0042:		// STREAM
								// DON'T CURRENTLY KNOW HOW TO HANDLE STREAM!
								ASSERT(FALSE);
								break;

							case 0x0043:		// STORAGE
								// DON'T CURRENTLY KNOW HOW TO HANDLE STORAGE!
								ASSERT(FALSE);
								break;

							case 0x0044:		// STREAMED_OBJECT
								// DON'T CURRENTLY KNOW HOW TO HANDLE STREAMED_OBJECT!
								ASSERT(FALSE);
								break;

							case 0x0045:		// STORED_OBJECT
								// DON'T CURRENTLY KNOW HOW TO HANDLE STORED_OBJECT!
								ASSERT(FALSE);
								break;

							case 0x0046:		// BLOB_OBJECT
								// DON'T CURRENTLY KNOW HOW TO HANDLE BLOB_OBJECT!
								ASSERT(FALSE);
								break;

							case 0x0047:		// CLIPBOARD_FORMAT
								// DON'T CURRENTLY KNOW HOW TO HANDLE CLIPBOARD_FORMAT!
								ASSERT(FALSE);
								break;

							case 0x0048:		// CLSID
								// DON'T CURRENTLY KNOW HOW TO HANDLE CLSID!
								ASSERT(FALSE);
								break;

							default:			// ??? --- Add future types here
								ASSERT(FALSE);
								break;
						}

						if (nPos % 4) WriteFormattedText(&nAddr, zData, (nPos % 4), nPos, "DWord Boundary Padding");

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

				if (pTempString) {
					free(pTempString);
					pTempString = NULL;
				}

				pTempString = DecodeTypeNameEntry(pObjectData->ofs_typename, tlbfile);
				if (pTempString == NULL) pTempString = strdup("???");

				WriteSectionBreak('=', 80, pTempString);
				if (pTempString) free(pTempString);
				pTempString = NULL;

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
					ObjectDataEntries[i].b_ismethod = (i < pObjectData->nMethodCount);
				}

				fseek(tlbfile, nSeekSave, SEEK_SET);

				nLocalOffset = 0ul;
				while (nLocalOffset < nInfoSize) {
					pObjectEntry = NULL;
					for (i=0; (((DWORD)i<nItemCount) && (pObjectEntry==NULL)); i++) {
						if (nLocalOffset == ObjectDataEntries[i].ofs_typeinfo) pObjectEntry = &ObjectDataEntries[i];
					}

					if ((pObjectEntry) && (pObjectEntry->ofs_typename != 0xFFFFFFFFul)) {
						pTempString = DecodeTypeNameEntry(pObjectEntry->ofs_typename, tlbfile);
						printf("Offset 0x%04lX = %s (%s):\n", nLocalOffset, ((pTempString != NULL) ? pTempString : "???"),
											((pObjectEntry->b_ismethod) ? "Method" : "Typedef"));

						if (pTempString) free(pTempString);
						pTempString = NULL;
					} else {
						printf("Offset 0x%04lX = ???:\n", nLocalOffset);
					}
					WriteSectionBreak('-', 60, "");

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
							case 0x80000003ul:
							case 0x80000016ul:
							case 0x8000001Eul:
								nTemp = zData2[3].dword[0];
								if (((nTemp >> 16) & 0xFFFFul) == 0x8C00) {
									nTemp = nTemp & 0xFFFF;
									if (nTemp & 0x8000) nTemp += 0xFFFF0000ul;
									WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 3, ": Value = 0x%08lX (%ld)",
																 nTemp, nTemp);
								} else {
									// TODO - Add logic here for const lookup:
									WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 3, ": Constant Table Offset = 0x%04lX",
																 nTemp);
								}
								break;

							case 0x80000019ul:
								WriteFormattedData(OME_WORDS, &nAddr, zData2, 1, 6, "    : ??? = 0x%04X (%d)",
															 zData2[3].word[0], zData2[3].word[0]);

								WriteFormattedData(OME_WORDS, &nAddr, zData2, 1, 7, "    : Index = %d", zData2[3].word[1]);
								break;

							default:
								WriteFormattedData(OME_WORDS, &nAddr, zData2, 1, 6, "    : ??? = 0x%04X (%d)",
															 zData2[3].word[0], zData2[3].word[0]);
								WriteFormattedData(OME_WORDS, &nAddr, zData2, 1, 7, "    : ??? = 0x%04X (%d)",
															 zData2[3].word[1], zData2[3].word[1]);
								break;
						}
					}

					if (nEntrySize >= 0x18) {
						//switch (nTypeCode & 0x8000FFFFul) {
						//	case 0x80000003ul:
						//	case 0x80000016ul:
						//	case 0x8000001Eul:
						//		nSubItemCount = 0;
						//		break;
						//	case 0x80000019ul:
						//		nSubItemCount = zData2[4].word[0];
						//		break;
						//	default:
						//		nSubItemCount = zData2[4].word[0];
						//		break;
						//}
						if (pObjectEntry->b_ismethod) {
							nSubItemCount = zData2[4].word[0];
						} else {
							nSubItemCount = 0;
						}
					} else {
						nSubItemCount = 0;
					}

					if (nEntrySize >= 0x18) {
						//switch (nTypeCode & 0x8000FFFFul) {
						//	case 0x80000003ul:
						//	case 0x80000016ul:
						//	case 0x8000001Eul:
						//		WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 4, ": Help Context = 0x%08lX", zData2[4].dword[0]);
						//		break;
						//	case 0x80000019ul:
						//		WriteFormattedData(OME_WORDS, &nAddr, zData2, 1, 8, "    : Argument Count = %d", nSubItemCount);
						//		WriteFormattedData(OME_WORDS, &nAddr, zData2, 1, 9, "    : Optional Argument Count = %d", zData2[4].word[1]);
						//		break;
						//	default:
						//		WriteFormattedData(OME_WORDS, &nAddr, zData2, 1, 8, "    : Argument Count = %d", nSubItemCount);
						//		WriteFormattedData(OME_WORDS, &nAddr, zData2, 1, 9, "    : Optional Argument Count = %d", zData2[4].word[1]);
						//		break;
						//}

						if (pObjectEntry->b_ismethod) {
								WriteFormattedData(OME_WORDS, &nAddr, zData2, 1, 8, "    : Argument Count = %d", nSubItemCount);
								WriteFormattedData(OME_WORDS, &nAddr, zData2, 1, 9, "    : Optional Argument Count = %d", zData2[4].word[1]);
						} else {
								WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 4, ": Help Context = 0x%08lX", zData2[4].dword[0]);
						}

					} else {
						if (pObjectEntry->b_ismethod) printf("                  : Argument Count = %d\n", nSubItemCount);
					}

					if ((nEntrySize >= 0x18) && ((nEntrySize - 0x18) > (nSubItemCount * 0x0C))) {
						if (!ReadData(&zData2, ((nEntrySize - 0x18 - (nSubItemCount * 0x0C))/4), tlbfile)) return;

						//switch (nTypeCode & 0x8000FFFFul) {
						//	case 0x80000019ul:
						//		WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 0, ": Help Context = 0x%08lX", zData2[0].dword[0]);
						//
						//		if (((nEntrySize - 0x18 - (nSubItemCount * 0x0C))/4) >= 2) {
						//			if ((zData2[1].dword[0] != 0xFFFFFFFFul) &&
						//				((zData2[1].dword[0] & 0x80000000ul) == 0)) {
						//
						//				pTempString = DecodeStringEntry(zData2[1].dword[0], tlbfile);
						//
						//				WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 1, ": HelpString : String Table Offset = 0x%04lX = \"%s\"",
						//												zData2[1].dword[0], ((pTempString != NULL) ? pTempString : "<ERROR-INVALID>"));
						//			} else {
						//				if (zData2[1].dword[0] == 0xFFFFFFFFul) {
						//					WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 1, ": HelpString : String Table Offset = -1 = <NONE>");
						//				} else {
						//					WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 1, ": ??? = 0x%04lX (%ld)",
						//												zData2[1].dword[0], zData2[1].dword[0]);
						//				}
						//			}
						//
						//			if (pTempString) {
						//				free(pTempString);
						//				pTempString = NULL;
						//			}
						//		}
						//
						//		for (i=2; (DWORD)i<((nEntrySize - 0x18 - (nSubItemCount * 0x0C))/4); i++) {
						//			WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, i, ": ??? = 0x%08lX (%ld)",
						//											zData2[i].dword[0], zData2[i].dword[0]);
						//		}
						//		break;
						//
						//	case 0x80000003ul:
						//	case 0x80000016ul:
						//	case 0x8000001Eul:
						//		if ((zData2[0].dword[0] != 0xFFFFFFFFul) &&
						//			((zData2[0].dword[0] & 0x80000000ul) == 0)) {
						//			pTempString = DecodeStringEntry(zData2[0].dword[0], tlbfile);
						//
						//			WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 0, ": HelpString : String Table Offset = 0x%04lX = \"%s\"",
						//											zData2[0].dword[0], ((pTempString != NULL) ? pTempString : "<ERROR-INVALID>"));
						//		} else {
						//			if (zData2[0].dword[0] == 0xFFFFFFFFul) {
						//				WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 0, ": HelpString : String Table Offset = -1 = <NONE>");
						//			} else {
						//				WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 0, ": ??? = 0x%04lX (%ld)",
						//											zData2[0].dword[0], zData2[0].dword[0]);
						//			}
						//		}
						//
						//		if (pTempString) {
						//			free(pTempString);
						//			pTempString = NULL;
						//		}
						//
						//		for (i=1; (DWORD)i<((nEntrySize - 0x18 - (nSubItemCount * 0x0C))/4); i++) {
						//			WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, i, ": ??? = 0x%08lX (%ld)",
						//											zData2[i].dword[0], zData2[i].dword[0]);
						//		}
						//		break;
						//
						//	default:
						//		WriteFormattedData(OME_DWORDS, &nAddr, zData2, ((nEntrySize - 0x18 - (nSubItemCount * 0x0C))/4), 0, "");
						//		break;
						//}


						nTemp = 0;
						if (pObjectEntry->b_ismethod) {
							WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 0, ": Help Context = 0x%08lX", zData2[0].dword[0]);
							nTemp++;

							if (((nEntrySize - 0x18 - (nSubItemCount * 0x0C))/4) >= 2) {
								if ((zData2[1].dword[0] != 0xFFFFFFFFul) &&
									((zData2[1].dword[0] & 0x80000000ul) == 0)) {

									pTempString = DecodeStringEntry(zData2[1].dword[0], tlbfile);

									WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 1, ": HelpString : String Table Offset = 0x%04lX = \"%s\"",
																	zData2[1].dword[0], ((pTempString != NULL) ? pTempString : "<ERROR-INVALID>"));
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

								nTemp++;
							}
						} else {
							if ((zData2[0].dword[0] != 0xFFFFFFFFul) &&
								((zData2[0].dword[0] & 0x80000000ul) == 0)) {
								pTempString = DecodeStringEntry(zData2[0].dword[0], tlbfile);

								WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 0, ": HelpString : String Table Offset = 0x%04lX = \"%s\"",
																zData2[0].dword[0], ((pTempString != NULL) ? pTempString : "<ERROR-INVALID>"));
							} else {
								if (zData2[0].dword[0] == 0xFFFFFFFFul) {
									WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 0, ": HelpString : String Table Offset = -1 = <NONE>");
								} else {
									WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 0, ": ??? = 0x%04lX (%ld)",
																zData2[0].dword[0], zData2[0].dword[0]);
								}
							}

							if (pTempString) {
								free(pTempString);
								pTempString = NULL;
							}

							nTemp++;
						}

						for (i=nTemp; (DWORD)i<((nEntrySize - 0x18 - (nSubItemCount * 0x0C))/4); i++) {
							WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, i, ": ??? = 0x%08lX (%ld)",
															zData2[i].dword[0], zData2[i].dword[0]);
						}
					}

					for (i=0; (DWORD)i<nSubItemCount; i++) {
						if (!ReadData(&zData2, 3, tlbfile)) return;

						printf("\nArgument %ld:\n", i+1);
						WriteSectionBreak('-', 20, "");

						pTemp = DecodeTypeCode(zData2[0].dword[0], tlbfile);
						WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 0, ": Type Code: 0x%08lX = %s", zData2[0].dword[0], ((pTemp != NULL) ? pTemp : "???"));
						if (pTemp) free(pTemp);

						if (zData2[1].dword[0] != 0xFFFFFFFFul) {
							pTempString = DecodeTypeNameEntry(zData2[1].dword[0], tlbfile);

							WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 1, ": Type Names Table Offset = 0x%04lX = \"%s\"",
															zData2[1].dword[0], ((pTempString != NULL) ? pTempString : "???"));
						} else {
							WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 1, ": Type Names Table Offset = -1 = retval");
						}

						if (pTempString) {
							free(pTempString);
							pTempString = NULL;
						}

						pTemp = DecodeArgumentType(zData2[2].dword[0]);
						WriteFormattedData(OME_DWORDS, &nAddr, zData2, 1, 2, ": %s", ((pTemp!=NULL) ? pTemp : "[???]"));
						if (pTemp) {
							free(pTemp);
							pTemp = NULL;
						}
					}
					if (nSubItemCount) printf("\n");

					printf("\n");
				}

				printf("Object Entry Table:\n");
				WriteSectionBreak('-', 20, "");

				for (i=0; (DWORD)i<nItemCount; i++) {
					if (!ReadData(&zData, 1, tlbfile)) return;

					pTempString = DecodeTypeNameEntry(ObjectDataEntries[i].ofs_typename, tlbfile);

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

					pTempString = DecodeTypeNameEntry(ObjectDataEntries[i].ofs_typename, tlbfile);

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

					pTempString = DecodeTypeNameEntry(ObjectDataEntries[i].ofs_typename, tlbfile);

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

