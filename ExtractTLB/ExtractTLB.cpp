// ExtractTLB.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#define VERSION 100

#define MAX_FIND_COUNT 16

typedef struct {
	unsigned long nAddrMSFT;
	unsigned long nSize;
	unsigned long nAddrPtr;
	int nGoodFlag;
} ADDR_STRUCT;

int main(int argc, char* argv[])
{
	FILE *infile;
	FILE *outfile;
	char temp;
	int Buffer[4];		// Rotating buffer of data read from file for finding "MSFT"
	int Buffer2[16];	// Rotating buffer of data read from file for finding pointer blocks

	unsigned long nFilePtr;
	ADDR_STRUCT nAddrInfo[MAX_FIND_COUNT];
	int nFound;
	int nGoodCount;
	int c;
	int i;

	fprintf(stderr, "Extract Type Library V%u.%02u\n", VERSION/100, VERSION%100);
	fprintf(stderr, "Copyright(c)2002 Dewtronics/Donald Whisnant\n\n");

	if (argc != 3) {
		fprintf(stderr, "Usage:  ExtractTLB <src-filename> <tlb-filename>\n\n");
		fprintf(stderr, "    Where:\n");
		fprintf(stderr, "            <src-filename> is a VB exe or dll executable file\n");
		fprintf(stderr, "            <tlb-filename> is the pathname of where to write the TLB file\n\n");
		fprintf(stderr,	"    Currently, this utility supports only VB files, though should expanded\n");
		fprintf(stderr, "        in the future to include VC++.  It has only been tested against\n");
		fprintf(stderr, "        VB 6.0, but might work with other versions.\n\n");
		return -1;
	}

	infile = fopen(argv[1], "rb");
	if (infile == NULL) {
		fprintf(stderr, "*** Error: Opening input file!\n\n");
		return 1;
	}

	if (access(argv[2], 0) == 0) {
		printf("\nFile %s exists! -- Overwrite? (y/n): ", argv[2]);
		fflush(stdout);
		temp=toupper(getchar());
		printf("\n\n");
		if (temp != 'Y') {
			fclose(infile);
			return 2;
		}

		if (access(argv[2], 2) != 0) {
			fprintf(stderr, "*** Error: Opening %s for writing\n\n", argv[2]);
			fclose(infile);
			return 2;
		}
	}

	outfile = fopen(argv[2], "wb");
	if (outfile == NULL) {
		fprintf(stderr, "*** Error: Opening %s for writing\n\n", argv[2]);
		fclose(infile);
		return 2;
	}

	printf("Finding Potential TLB Sections...\n");

	memset(Buffer, 0, sizeof(Buffer));

	nFilePtr = 0;
	nFound = 0;
	while (!feof(infile)) {
		c = fgetc(infile);
		if (c == EOF) continue;
		for (i=1; i<4; i++) {
			Buffer[i-1] = Buffer[i];
		}
		Buffer[3] = c;
		if (nFilePtr >= 3) {
			if ((Buffer[0] == 'M') &&
				(Buffer[1] == 'S') &&
				(Buffer[2] == 'F') &&
				(Buffer[3] == 'T')) {
				printf("Found Entry at 0x%04lX", nFilePtr - 3);
				if (nFound < MAX_FIND_COUNT) {
					printf("\n");
					nAddrInfo[nFound].nAddrMSFT = nFilePtr - 3;
					nAddrInfo[nFound].nSize = 0;			// No size until we find the pointer block
					nAddrInfo[nFound].nGoodFlag = 0;		// Not good yet until we find the Pointer Block
					nFound++;
				} else {
					printf("  *** TOO MANY FOUND, IGNORING THIS ONE\n           - Change MAX_FIND_COUNT and Recompile\n");
					nFound++;
				}
			}
		}

		nFilePtr++;
	}

	if (nFound == 0) {
		printf("\n*** Error: Didn't find any TLB sections.  Verify you are using the correct input file!\n\n");
		fclose(infile);
		fclose(outfile);
		return 3;
	}

	printf("\nFound: %ld potential entries\n\n", nFound);

	printf("Searching for Corresponding Headers...\n");

	memset(Buffer2, 0, sizeof(Buffer2));

	fseek(infile, 0ul, SEEK_SET);
	nFilePtr = 0;
	nGoodCount = 0;
	while (!feof(infile)) {
		c = fgetc(infile);
		if (c == EOF) continue;
		for (i=1; i<16; i++) {
			Buffer2[i-1] = Buffer2[i];
		}
		Buffer2[15] = c;
		if (nFilePtr >= 15) {
			for (i=0; i<nFound; i++) {
				if ((Buffer2[0] == (int)(nAddrInfo[i].nAddrMSFT & 0xFF)) &&
					(Buffer2[1] == (int)((nAddrInfo[i].nAddrMSFT >> 8) & 0xFF)) &&
					(Buffer2[2] == (int)((nAddrInfo[i].nAddrMSFT >> 16) & 0xFF)) &&
					(Buffer2[3] == (int)((nAddrInfo[i].nAddrMSFT >> 24) & 0xFF)) &&
					(Buffer2[8] == 0xB0) &&
					(Buffer2[9] == 0x04) &&
					(Buffer2[10] == 0x00) &&
					(Buffer2[11] == 0x00) &&
					(Buffer2[12] == 0x00) &&
					(Buffer2[13] == 0x00) &&
					(Buffer2[14] == 0x00) &&
					(Buffer2[15] == 0x00)) {
					nAddrInfo[i].nGoodFlag = 1;
					nAddrInfo[i].nAddrPtr = nFilePtr - 15;
					nAddrInfo[i].nSize =	(Buffer2[7] << 24) +
											(Buffer2[6] << 16) +
											(Buffer2[5] << 8) +
											(Buffer2[4]);
					printf("Found Header at 0x%04lX for Entry 0x%04lX of size 0x%04lX\n",
									nAddrInfo[i].nAddrPtr, nAddrInfo[i].nAddrMSFT, nAddrInfo[i].nSize);
					nGoodCount++;
				}
			}
		}

		nFilePtr++;
	}

	if (nGoodCount == 0) {
		printf("\n*** Error: Didn't find any corresponding TLB section heading.  Verify you are using the correct input file!\n\n");
		fclose(infile);
		fclose(outfile);
		return 4;
	}

	if (nGoodCount > 1) {
		printf("\nFound: %ld valid entries\n\n", nGoodCount);
		printf("\n*** Error: I don't know what to do with more than 1!!!\n\n");
		fclose(infile);
		fclose(outfile);
		return 5;
	}

	printf("\nWriting TLB...\n");

	for (i=0; i<nFound; i++) {
		if (nAddrInfo[i].nGoodFlag) {
			fseek(infile, nAddrInfo[i].nAddrMSFT, SEEK_SET);
			while ((!feof(infile)) && (nAddrInfo[i].nSize)) {
				c = fgetc(infile);
				if (c == EOF) continue;
				fputc(c, outfile);
				nAddrInfo[i].nSize--;
			}
			break;
		}
	}

	fclose(infile);
	fclose(outfile);

	printf("\nDone...\n\n");
	return 0;
}

