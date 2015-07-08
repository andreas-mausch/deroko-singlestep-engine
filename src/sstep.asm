.586p 
.model        flat, stdcall
locals
jumps

include              shitheap.inc

.data
kernel32             dd            ?
sstep                db            "y0 mY nIgGaZ...", 0
sstep1               db            "nIgGaZ...",       0
.code
__start:  
                     push          offset sehhandle
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
                     callW         MessageBoxA
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
                     db            "START_SEH", 0
sehhandle            label         near
                     push          ebp
                     mov           ecx, dword ptr[esp + 8]
                     mov           ebx, dword ptr[esp + 10h]
                     mov           [ebx.CONTEXT_Dr0], eax
                     mov           [ebx.CONTEXT_Dr1], eax
                     mov           [ebx.CONTEXT_Dr2], eax
                     mov           [ebx.CONTEXT_Dr3], eax
                     call          delta
delta:               inc           eax
                     mov           ebp, dword ptr[esp]
                     add           esp, 4
                     cmp           [ecx.ER_ExceptionCode], EXCEPTION_BREAKPOINT
                     je            __restore_opcode
                     cmp           [ecx.ER_ExceptionCode], EXCEPTION_SINGLE_STEP
                     jne           __exit_seh
                     xor           eax, eax
                     cmp           dword ptr [ebp + imagebase - delta], eax
                     jne           __check_range
                     mov           esi, [ebx.CONTEXT_Eip]
                     and           esi, 0FFFF0000h 
                     mov           eax, not 'ZMED' 
                     not           eax           
                     rol           eax, 16                          
__get_base:          cmp           word ptr[esi], ax               
                     je            __got_base              
                     sub           esi, 1000h
                     jmp           __get_base
__got_base:          mov           dword ptr [ebp + imagebase - delta], esi               ;save base
__check_range:       mov           esi, [ebx.CONTEXT_Eip]
                     mov           edi, dword ptr[ebp + imagebase - delta]
                     and           esi, 0FFF00000h
                     cmp           esi, edi
                     jne           __out_of_range
__decode:                 
                     mov           eax, dword ptr[ebp + prev - delta]
                     test          eax, eax         
                     jz            __skip_prev
                     xchg          eax, edx
                     mov           eax, dword ptr[ebp + prev_len - delta]          
                     mov           cl, byte ptr[ebp + xor_key - delta]
__crypt_prev:        dec           eax
                     xor           byte ptr[edx+eax], cl
                     test          eax, eax
                     jnz           __crypt_prev                                        
__skip_prev:                     
                     mov           esi, [ebx.CONTEXT_Eip]
                     mov           dword ptr[ebp + prev - delta], esi                     ;set prev for next cycle
                     lea           edi, [ebp + buffer - delta]
                     mov           ecx, 4
                     cld
                     rep           movsd
                                          
                     mov           ecx, 16
                     sub           edi, 16                                                 ;buffer
                     mov           dl, byte ptr[ebp + xor_key - delta]
__decrypt_buf:       dec           ecx
                     xor           byte ptr[edi+ecx], dl
                     test          ecx, ecx
                     jnz           __decrypt_buf
                     
                     push          edi
                     call          ldex86                                                  ;get len of instr
                     mov           dword ptr[ebp + prev_len - delta], eax
                     mov           edi, [ebx.CONTEXT_Eip]
                     mov           dl, byte ptr[ebp + xor_key - delta]
__decrypt_eip:       dec           eax
                     xor           byte ptr[edi+eax], dl
                     test          eax, eax
                     jnz           __decrypt_eip
                     xor           eax, eax
                     or            [ebx.CONTEXT_EFlags], 100h
                     jmp           __exit_seh
                                        
__out_of_range:      mov           esi, [ebx.CONTEXT_Esp]
                     mov           esi, dword ptr[esi]                                     ;get saved EIP
                     push          dword ptr[esi]
                     pop           dword ptr[ebp + opcode - delta]
                     mov           dword ptr[esi], 0CCh
                     xor           eax, eax
                     and           [ebx.CONTEXT_EFlags], 0FFFFFEFFh
                     jmp           __exit_seh
__restore_opcode:    mov           esi, [ebx.CONTEXT_Eip]
                     push          dword ptr[ebp + opcode - delta]
                     pop           dword ptr[esi]
                     jmp           __decode               
__exit_seh:          pop           ebp
                     ret

imagebase            dd            0                                                       ;imagebase
prev                 dd            0                                                       ;prev pointer
prev_len             dd            0                                                       ;len of prev                   
buffer               db            16     dup(0)                                           ;buffer
opcode               dd            0                                                       ;opcode
xor_key              db            0DEh                                                    ;xor key randomly                                                                                          
include              ldex86bin.inc
                     db            "END_SEH", 0
end                  __start