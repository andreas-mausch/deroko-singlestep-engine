.586p 
.model        flat, stdcall
locals
jumps

include              c:\tasm32\include\shitheap.inc
include              c:\tasm32\include\extern.inc
.data
kernel32             dd            ?
sstep                db            "y0 mY nIgGaZ...", 0
sstep1               db            "nIgGaZ...",       0
.code
public  C start
start:  
                     mov           eax, offset xor_key
                     mov           byte ptr[eax], 0DEh 
                     mov           eax, offset imagebase       
                     mov           dword ptr[eax], 0
                     mov           dword ptr[eax + 4], 0
                     push          offset seh32bin
                     push          dword ptr FS:[0]
                     mov           dword ptr FS:[0], esp
                     
                     
                     pushfd        
                     or            dword ptr[esp] , 100h
                     popfd
                     jmp           Crypted_By_Eip
                     db            "START",0                  
                                      
Crypted_By_Eip:    
                     call          KernelBase
                     mov           kernel32, eax
                     call          KernelBase
                     
                     gethash       <LoadLibraryA>                                
                     push          hash
                     push          kernel32
                     call          GetProc
                     
                     x_push        ebx, <user32.dll~>
                     push          esp
                     call          eax
                     x_pop
                     
                     gethash       <MessageBoxA>
                     push          hash   
                     push          eax
                     call          GetProc
                     
                     xor           edx, edx
                     push          edx
                     push          offset sstep1
                     push          offset sstep
                     push          edx
                     call          eax
                                         
                     call          __test
                     
                     gethash       <ExitProcess>                    
                     push          hash
                     push          kernel32
                     call          GetProc                                   
                     
                     xor           edx, edx
                     push          edx
                     call          eax

                     ;--------------------- Testing procedure ---------------------
__test               label         near
                     push          ebp
                     mov           ebp, esp
                     fninit
                     
                     gethash       <IsDebuggerPresent>
                     push          hash                                 
                     push          kernel32
                     call          GetProc
                     call          eax
                     test          eax, eax
                     jz            __exit_test
                     
                     xor           edx, edx
                     x_push        ebx, <Are you tired of tracing????~>
                     mov           ebx, esp
                     push          edx
                     push          ebx
                     push          ebx
                     push          edx
                     call          MessageBoxA
                     x_pop
                     
                     gethash       <OutputDebuggStringA>
                     push          hash                                  
                     push          kernel32
                     call          GetProc
                                          
                     x_push        ebx, <It is not nice to trace someones work~>
                     push          esp
                     call          eax 
                     x_pop
                     push          0DEADC0DEh
                     ret
__exit_test:         leave
                     ret
                     ;--------------------- Kernel32 DLL base ---------------------
KernelBase           label         near
                     xor           edx, edx
                     mov           esi, dword ptr FS:[edx]
__seh:               lodsd
                     cmp           eax, 0FFFFFFFFh
                     je            __find_kernel
                     mov           esi, eax
                     jmp           __seh  
__find_kernel:       mov           edi, dword ptr[esi+4]         
                     and           edi, 0FFFF0000h     
__spin1:             cmp           word ptr[edi], 'ZM'      
                     jz            __test_pe
                     sub           edi, 10000h
                     jmp           __spin1  
__test_pe:           mov           ebx, edi
                     add           ebx, [ebx.MZ_lfanew]
                     cmp           word ptr[ebx],'EP'
                     je            __ret_kernel_base
                     jmp           __spin1   
__ret_kernel_base:   mov           eax, edi
                     ret

                     ;--------------------- GetProcAddress using HASH ---------------------
GetProc              label         near
                     handle equ dword ptr[esp+4]
                     lhash  equ dword ptr[esp+8]
                     
                     mov           ebx, handle
                     mov           ecx, ebx
                     add           ebx, [ebx.MZ_lfanew]			
                     mov           ebx, [ebx.NT_OptionalHeader.OH_DirectoryEntries.DE_Export.DD_VirtualAddress]
                     add           ebx, ecx
                     mov           edi, [ebx.ED_AddressOfNames]
                     add           edi, ecx
                     xor           esi, esi                           ;esi counter                  				
__find_api:          lea           edx, dword ptr[edi+esi*4]
                     mov           edx, dword ptr[edx]			
                     add           edx, ecx				
                     xor           eax, eax				
__2:                 rol           eax, 7					;hash algo  (x) by z0mbie
                     xor           al, byte ptr [edx]
                     inc           edx					
                     cmp           byte ptr [edx], 0			
                     jnz           __2					
                     cmp           eax, lhash             	       
                     je            __find_ordinal				    
                     inc           esi					
                     cmp           esi, [ebx.ED_NumberOfNames]		
                     jb            __find_api                    
__find_ordinal:      mov           edx, [ebx.ED_AddressOfOrdinals]	
                     add           edx, ecx				
                     movzx         edx, word ptr [edx+esi*2]		
                     mov           eax, [ebx.ED_AddressOfFunctions]	
                     add           eax, ecx				
                     mov           eax, [eax+edx*4]			
                     add           eax, ecx				
__end:	       	ret           8                
End_Crypt_By_Eip:                     
                     db            "END", 0
include              seh32bin.inc       
end                  start