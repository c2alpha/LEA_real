#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_MARKER_LEN 50

/**
 * @brief Find "marker" from the "infile"
 * 
 * @param infile Input file pointer
 * @param marker Input character array that want to find from the "infile"
 * @return If we fine return 1, else return 0
 */
int		FindMarker(FILE* infile, const char* marker);

/**
 * @brief From the input file "infile", reads some characters of length "Length" after the "str".
 *        And store it in "A"
 * 
 * @param infile Input file pointer
 * @param A Destination space 
 * @param Length The length of characters that we want to read
 * @param str str을 찾고 그 뒤에 나오는 문장을 읽을때 사용하는 애...
 * @return If we read appropriately, return 1. If not, return 0
 */
int		ReadHex(FILE* infile, unsigned char* A, int Length, char* str);

/**
 * @brief Write down two inputs "S" and "A" to the file fp 
 * 
 * @param fp Output file pointer
 * @param S Firstly we write down this parameter to fp
 * @param A And then write this parameter to fp
 * @param L The length of "A"
 */
void	fprintBstr(FILE* fp, char* S, unsigned char* A, unsigned long long L);