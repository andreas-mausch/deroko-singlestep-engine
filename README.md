# Single step decryption/encryption engine
**Author: deroko**

Ok this is engine used for the first time in viri world in blacky.w2k/xp viri.
Idea of this engine is to screw heuristics and emulation one and for all.

Also this engine might be used in some other code where protection is needed.
Basicaly this engine works with TRAP FLAG in Eflags register, which will cause
exception after each instruction. When exception is generated code will decrypt
current instruction and encrypt previous instruction and so on...
due to exception whole engine is designed as Structure Exception Handler (SEH)...

Decryption routine is very simple xor with random key which you specify.
This gives us 256 generations of a same viri.  
Here is data used with this engine:

```
imagebase            dd            0
                     - if you are using this from viri don't forget to set this
                     one to 0 before entering single step, this will be used
                     to check if EIP is in range (calls to APIs)

prev                 dd            0
                     - pointer to prev instruction, also set to 0 before entering
                     sstep decryption/encryption...
prev_len             dd            0
                     - len of previous instruction, so we don't have to call lde
                     2 times
buffer               db            16     dup(0)
                     - this is used so instruction can be decoded in separate buffer
                     and to determine its length so we know how much to decrypt at EIP

opcode               dd            0
                     - used to save opcode when EIP is out-of-imagebase and to insert
                     int 3h there (just regular step over)
xor_key              db            0DEh
                     - this key is 0DEh only for first generation, you can change it
                     to something else if you want... (also change runtime.c)
include              ldex86bin.inc
                     - length disassembler engine (written by me) used to fin len of
                     instructions....
```

#### Usage example
```
                     push   seh32bin
                     push dword ptr FS:[0]
                     mov dword ptr FS:[0], esp
                     pushfd
                     or dword ptr[esp], 100h
                     popfd
                     jmp __encrypted_code ;(1st instruction ain't traced)
```

#### Usage example in viri
```
                     call delta
delta:               pop ebp
                     sub ebp, offset delta
                     lea eax, [ebp+seh32bin]
                     push eax
                     sub eax, eax
                     push dword ptr FS:[eax]
                     mov dword ptr FS:[eax], esp
                     ;0 imagebase and prev
                     mov [ebp+imagebase], eax
                     mov [ebp+prev], eax
                     mov eax, 100h
                     push eax
                     popfd
                     jmp __encrypted_code
```

Also you should "Escape from SEH" b/c whole code ain't crypted... it is achived
by setting new SEH handle and clearing trap-flag:
```
                     push offset escape_seh
                     push dword ptr FS:[0]
                     mov dword ptr FS:[0], esp

__escape:
                     pop dword ptr FS:[0]
                     add esp, 4
                     pop dword ptr FS:[0]
                     add esp, 4

escape_seh:
                     mov ebx, dword ptr [esp+0Ch]
                     and [ebx.CONTEXT_EFlgags], 0FFFFFEFFh     ; clean trap flag
                     mov [ebx.CONTEXT_Eip], offset __escape    ; offset of clean code
                     xor eax, eax
                     ret
```
runtime.c is tool created to crypt code, it will scan for strings:  
                     db "START",0 and db "END", 0

START + 0 will be changed with 6x0FFh  
END + 0 will be changed with 4x90h

well that's it about sstep engine...

*deroko  
http://deroko.phearless.org*

#### Sources
* sstep.asm     &lt;whole engine&gt;
* sstep1.asm    &lt;testing bin dump of engine&gt;  
* ldex86bin.inc &lt;length disassembler engine - bin dump&gt;  
* seh32bin.inc  &lt;sstep decryption encryption engine - bin dump&gt;

sorry for ma bad english... it ain't my native language...
