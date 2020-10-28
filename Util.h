#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_MARKER_LEN 50


int		FindMarker(FILE* infile, const char* marker);
int		ReadHex(FILE* infile, unsigned char* A, int Length, char* str);
void	fprintBstr(FILE* fp, char* S, unsigned char* A, unsigned long long L);