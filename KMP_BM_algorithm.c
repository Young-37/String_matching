#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <io.h>

#define FALSE 0
#define TRUE 1

#define MAXSIZE 100
#define XSIZE 512
#define ASIZE 512

typedef struct _finddata_t FILE_SEARCH;

void PRE_KMP(char *Pattern, int PatternSize, int kmp_next[]);
int KMP(char *Text, char *Pattern, int TextSize, int PatternSize);

void PRE_BC(char *Pattern, int PatternSize, int bm_bc[]);
void PRE_GS(char *Pattern, int PatternSize, int bm_gs[]);
int TBM(char *Text, char *Pattern, int TextSize, int PatternSize);

int MAX(int x, int y);

void GetFileListKMP(char* path, char virusPattern[XSIZE][XSIZE], int PatternSize);
void GetFileListBM(char* path, char virusPattern[XSIZE][XSIZE], int PatternSize);

int main(int argc, char* argv[])
{
	int i, j, isStop;
	int virusPatternSize = -1;
	char programCodePath[MAXSIZE], virusCode[XSIZE];
	char virusPattern[XSIZE][XSIZE];
	clock_t startTime, endTime;
	
	while(virusPatternSize <= 0)
	{
		printf("Enter the VIRUS PATTERN SIZE\n >>");
		scanf("%d", &virusPatternSize);
		rewind(stdin);
		
		if(virusPatternSize <= 0)
			printf("VIRUS PATTERN SIZE must be greater than 0 \n\n");
	}
	
	printf("\nEnter the VIRUS CODE \n >>");
	scanf("%s", &virusCode);
	rewind(stdin);

	//////////////// 악성코드 패턴 생성 ////////////////
	isStop = FALSE;
	for (i = 0; i < XSIZE; i++)
	{
		for (j = 0; j < virusPatternSize; j++)
		{
			if (virusCode[i + j] == '\0')
			{
				isStop = TRUE;
				virusPattern[i][0] = '\0';
				break;
			}
			
			virusPattern[i][j] = virusCode[i + j];
		}
		if (isStop)
			break;
	}
	 
	printf("\n================== Virus Pattern ================== \n");
	for (i = 0; i < XSIZE; i++)
	{
		if (virusPattern[i][0] == '\0')
		{
			printf("\n");
			break;
		}
			
		printf("%s  ", virusPattern[i]);
	}

	printf("\nEnter the PATH of PROGRAM CODE \n >>");
	scanf("%s", &programCodePath);
	rewind(stdin);
	
	printf("\n================== KMP ================== \n");
	startTime = clock();
	GetFileListKMP(programCodePath, virusPattern, virusPatternSize);
	endTime = clock();
	printf("\nKMP Time: %.3lf ms\n", (double)(endTime - startTime));
	
	printf("\n================== BM ================== \n");
	startTime = clock();
	GetFileListBM(programCodePath, virusPattern, virusPatternSize);
	endTime = clock();
	printf("\nBM Time: %.3lf ms\n", (double)(endTime - startTime));
	
	printf("\n프로그램을 종료하려면 아무키나 눌러주세요...\n");
	getch();
	
	printf("Thank you :)\n");
	return 0;
}

//////////////// KMP ////////////////
void PRE_KMP(char *Pattern, int PatternSize, int kmp_next[])
{
	int i = 0;
	int j = kmp_next[0] = -1;
	
	while(i < PatternSize)
	{
		while(j > -1 && Pattern[i] != Pattern[j])
			j = kmp_next[j];
			
		i++;
		j++;
		
		if(Pattern[i] == Pattern[j])
			kmp_next[i] = kmp_next[j];
		else
			kmp_next[i] = j;
	}
}

int KMP(char *Text, char *Pattern, int TextSize, int PatternSize)
{
	int kmp_next[XSIZE];
	int i = 0;
	int j = 0;
	int Position = -1;
	
	PRE_KMP(Pattern, PatternSize, kmp_next);
	
	i = j = 0;
	
	while(i < TextSize)
	{
		while(j > -1 && Pattern[j] != Text[i])
			j = kmp_next[j];
			
		i++;
		j++;
		
		if(j >= PatternSize)
		{
			Position = i - j;
			j = kmp_next[j];
		}
	}
	
	return Position;
}

//////////////// BM ////////////////
void PRE_BC(char *Pattern, int PatternSize, int bm_bc[])
{
	int a, j;
	
	for (a = 0; a < ASIZE; a++)
	{
		bm_bc[a] = PatternSize;
	}
		
	for (j = 0; j < PatternSize - 1; j++)
	{
		bm_bc[Pattern[j]] = PatternSize - j - 1;
	}
}

void PRE_GS(char *Pattern, int PatternSize, int bm_gs[])
{
	int i, j, p, f[XSIZE];
	
	memset(bm_gs, 0, (PatternSize + 1) * sizeof(int));
	
	f[PatternSize] = j = PatternSize + 1;
	
	for (i = PatternSize; i > 0; i--)
	{
		while (j <= PatternSize && Pattern[i - 1] != Pattern[j - 1])
		{
			if (bm_gs[j] == 0)
			{
				bm_gs[j] = j - i;
			}
			j = f[j];
		}
		f[i - 1] = --j;
	}
	
	p = f[0];
	for (j = 0; j <= PatternSize; ++j)
	{
		if (bm_gs[j] == 0)
		{
			bm_gs[j] = p;
		}
		if (j == p)
		{
			p = f[p];
		}
	}
}

int TBM(char *Text, char *Pattern, int TextSize, int PatternSize)
{
	int i, j;
	int bm_gs[XSIZE], bm_bc[ASIZE];
	int Position = -1;
	
	PRE_GS(Pattern, PatternSize, bm_gs);
	PRE_BC(Pattern, PatternSize, bm_bc);
	
	i = 0;
	while(i <= TextSize - PatternSize)
	{
		for (j = PatternSize - 1; j >= 0 && Text[i + j] == Pattern[j]; --j);
		if (j < 0)
		{
			Position = i;
			i += bm_gs[j + 1];
		}
		else
		{
			i += MAX(bm_gs[j + 1], bm_bc[Text[i + j]] - PatternSize + j + 1);
		}
	}

	return Position;
}

int MAX(int x, int y)
{
	if (x > y)
	{
		return x;
	}
	else
	{
		return y;
	}
}

//////////////// KMP 실행 ////////////////
void GetFileListKMP(char* path, char virusPattern[XSIZE][XSIZE], int PatternSize)
{
	int numKMPVirusO = 0;
	int numKMPVirusX = 0;
	
	char KMPVirusList[MAXSIZE][MAXSIZE], KMPCleanList[MAXSIZE][MAXSIZE];
	
	int i, Position, havingVirus;
	long h_file;
	char search_path[MAXSIZE], file[MAXSIZE], buffer[XSIZE];
	FILE *fp, *KMPresult;
	
	KMPresult = fopen("report1_2017112596_KMP_result.txt", "wt");
	fprintf(KMPresult, "================== KMP ================== \n");
	
	FILE_SEARCH file_search;
	
	sprintf(search_path, "%s/*.*", path);
	if((h_file = _findfirst(search_path, &file_search)) == -1L)
	{
		printf("\nNo files in current directory!\n");
	}
	else
	{
		do{
			memcpy(file, path, MAXSIZE);
			strcat(file, file_search.name);
			fp = fopen(file, "rt");
			if (fp != NULL)
			{
				havingVirus = FALSE;
				fprintf(KMPresult, "\n File: %s\n", file);
			
				fgets(buffer, sizeof(buffer), fp);
				fprintf(KMPresult, "Program Code: %s\n", buffer);
				
				for (i = 0; i < XSIZE; i++)
				{
					if (virusPattern[i][0] == '\0')
					{
						break;
					}
					
					Position = KMP(buffer, virusPattern[i], strlen(buffer), PatternSize);
					
					if(Position >= 0)
					{
						fprintf(KMPresult, "KMP: column: %d : %s \n", Position + 1, virusPattern[i]);
						havingVirus = TRUE;
					}
				}
				
				if (havingVirus)
				{
					memcpy(KMPVirusList[numKMPVirusO], file, MAXSIZE);
					numKMPVirusO++;
				}
				else
				{
					memcpy(KMPCleanList[numKMPVirusX], file, MAXSIZE);
					numKMPVirusX++;
				}
			}	
			fclose(fp);
		} while(_findnext(h_file, &file_search) == 0);
		
		_findclose(h_file);
	}
	printf("\nVirus O : %d\n", numKMPVirusO);
	for (i = 0; i < numKMPVirusO; i++)
	{
		printf("%s\n", KMPVirusList[i]);
	}
	
	printf("\nVirus X : %d\n", numKMPVirusX);
	for (i = 0; i < numKMPVirusX; i++)
	{
		printf("%s\n", KMPCleanList[i]);
	}
	
	printf("\nDetails are in report1_2017112596_KMP_result.txt\n");
	fclose(KMPresult);
}

//////////////// BM 실행 ////////////////
void GetFileListBM(char* path, char virusPattern[XSIZE][XSIZE], int PatternSize)
{
	int numBMVirusO = 0;
	int numBMVirusX = 0;
	
	char BMVirusList[MAXSIZE][MAXSIZE], BMCleanList[MAXSIZE][MAXSIZE];

	int i, Position, havingVirus;
	long h_file;
	char search_path[MAXSIZE], file[MAXSIZE], buffer[XSIZE];
	FILE *fp, *BMresult;
	
	BMresult = fopen("report1_2017112596_BM_result.txt", "wt");
	fprintf(BMresult, "================== BM ================== \n");
	
	FILE_SEARCH file_search;
	
	sprintf(search_path, "%s/*.*", path);
	if((h_file = _findfirst(search_path, &file_search)) == -1L)
	{
		printf("\nNo files in current directory!\n");
	}
	else
	{
		do{
			memcpy(file, path, MAXSIZE);
			strcat(file, file_search.name);
			fp = fopen(file, "rt");
			if (fp != NULL)
			{
				havingVirus = FALSE;
				fprintf(BMresult, "\n File: %s\n", file);
			
				fgets(buffer, sizeof(buffer), fp);
				fprintf(BMresult, "Program Code: %s\n", buffer);
				
				for (i = 0; i < XSIZE; i++)
				{
					if (virusPattern[i][0] == '\0')
					{
						break;
					}
					
					Position = TBM(buffer, virusPattern[i], strlen(buffer), PatternSize);
					
					if(Position >= 0)
					{
						fprintf(BMresult, "BM: column: %d : %s \n", Position + 1, virusPattern[i]);
						havingVirus = TRUE;
					}
				}
				
				if (havingVirus)
				{
					memcpy(BMVirusList[numBMVirusO], file, MAXSIZE);
					numBMVirusO++;
				}
				else
				{
					memcpy(BMCleanList[numBMVirusX], file, MAXSIZE);
					numBMVirusX++;
				}
			}	
			fclose(fp);
		} while(_findnext(h_file, &file_search) == 0);
		
		_findclose(h_file);
	}
	printf("\nVirus O : %d\n", numBMVirusO);
	for (i = 0; i < numBMVirusO; i++)
	{
		printf("%s\n", BMVirusList[i]);
	}
	
	printf("\nVirus X : %d\n", numBMVirusX);
	for (i = 0; i < numBMVirusX; i++)
	{
		printf("%s\n", BMCleanList[i]);
	}
	
	printf("\nDetails are in report1_2017112596_BM_result.txt\n");
	fclose(BMresult);
}
