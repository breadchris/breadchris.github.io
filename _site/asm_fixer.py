
code="""
.text:08048B17                 mov     esi, ds:ptr[esi*4]
.text:08048B1E                 mov     esi, [esi+4]
.text:08048B21                 mov     esi, [esi-4]
.text:08048B24                 mov     [esp], eax      ; s
.text:08048B27                 mov     dword ptr [esp+4], 40h ; maxlen
.text:08048B2F                 mov     [esp+8], edx    ; format
.text:08048B33                 mov     [esp+0Ch], esi
.text:08048B37                 mov     [ebp+var_8], ecx
.text:08048B3A                 call    _snprintf
""".split("\n")[1:-1]

for c in code:
    print c.replace("                 ", ":     ") \
           .replace("               ", " ")
