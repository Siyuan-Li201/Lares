{
  void *v1; // edi
  int v2; // edx
  int v3; // eax
  int v4; // esi
  __int16 v5; // kr00_2
  int v6; // eax
  int v7; // edi
  int v9; // eax
  int v10; // esi
  int v11; // esi
  int v12; // eax
  int v13; // ecx
  int v14; // esi
  int v15; // eax
  int v16; // edi
  void *v17; // esi
  int v18; // eax
  int v19; // eax
  size_t v20; // eax
  int v21; // eax
  size_t v22; // eax
  int v23; // eax
  int v24; // esi
  int v25; // edx
  int v26; // eax
  int v27; // edx
  int v28; // eax
  int v29; // eax
  int v30; // eax
  int v31; // edx
  int v32; // eax
  int v33; // esi
  int v34; // esi
  int v35; // eax
  int v36; // edx
  int v37; // eax
  size_t v38; // esi
  int v39; // esi
  int v40; // eax
  int v41; // eax
  size_t v42; // eax
  char v43; // cl
  int v44; // esi
  _DWORD *v45; // eax
  int (__cdecl *v46)(int, _DWORD, char *, int, char *, int); // edx
  unsigned int v47; // eax
  size_t v48; // edi
  _DWORD *v49; // eax
  char *v50; // eax
  int v51; // edx
  size_t v52; // edx
  int v53; // eax
  int v54; // ecx
  int v55; // [esp-10h] [ebp-308h]
  size_t v56; // [esp-8h] [ebp-300h]
  size_t n; // [esp+Ch] [ebp-2ECh]
  size_t na; // [esp+Ch] [ebp-2ECh]
  void *dest; // [esp+10h] [ebp-2E8h]
  void *desta; // [esp+10h] [ebp-2E8h]
  size_t v61; // [esp+14h] [ebp-2E4h]
  size_t v62; // [esp+14h] [ebp-2E4h]
  size_t v63; // [esp+14h] [ebp-2E4h]
  size_t v64; // [esp+14h] [ebp-2E4h]
  size_t v65; // [esp+18h] [ebp-2E0h]
  void *v66; // [esp+18h] [ebp-2E0h]
  size_t v67; // [esp+18h] [ebp-2E0h]
  size_t v68; // [esp+18h] [ebp-2E0h]
  size_t v69; // [esp+18h] [ebp-2E0h]
  size_t v70; // [esp+18h] [ebp-2E0h]
  _BYTE *v71; // [esp+1Ch] [ebp-2DCh]
  int v72; // [esp+1Ch] [ebp-2DCh]
  size_t v73; // [esp+2Ch] [ebp-2CCh] BYREF
  char v74[6]; // [esp+30h] [ebp-2C8h] BYREF
  char v75[32]; // [esp+36h] [ebp-2C2h] BYREF
  char s[4]; // [esp+56h] [ebp-2A2h] BYREF
  int v77; // [esp+D4h] [ebp-224h]
  char src; // [esp+D8h] [ebp-220h] BYREF
  char v79; // [esp+D9h] [ebp-21Fh]
  char v80[514]; // [esp+DAh] [ebp-21Eh] BYREF
  unsigned int v81; // [esp+2DCh] [ebp-1Ch]

  v81 = __readgsdword(0x14u);
  if ( *(_DWORD *)(a1 + 52) != 4480 )
    return sub_80AB000(a1, 22);
  v71 = *(_BYTE **)(*(_DWORD *)(a1 + 60) + 4);
  v1 = v71 + 4;
  v2 = *(_DWORD *)(*(_DWORD *)(*(_DWORD *)(a1 + 88) + 836) + 12);
  if ( (v2 & 1) == 0 )
  {
    if ( (v2 & 0xE) != 0 )
    {
      v21 = *(_DWORD *)(*(_DWORD *)(a1 + 192) + 152);
      if ( v21 )
      {
        v22 = *(_DWORD *)(v21 + 112);
        v67 = v22;
        if ( v22 )
        {
          v23 = sub_81154B0(v22);
          v24 = v23;
          if ( v23 )
          {
            if ( sub_8115C30(v23) )
            {
              v25 = sub_8115C40(v1, *(_DWORD *)(v67 + 20), v24);
              if ( v25 > 0 )
              {
                v62 = v25;
                v68 = *(_DWORD *)(a1 + 192);
                *(_DWORD *)(v68 + 16) = (*(int (__cdecl **)(int, size_t, void *))(*(_DWORD *)(*(_DWORD *)(a1 + 8) + 100)
                                                                                + 12))(
                                          a1,
                                          v68 + 20,
                                          v1);
                memset(v1, 0, v62);
                v26 = sub_80FB010(*(_DWORD *)(v24 + 20));
                v27 = v26 + 14;
                v28 = v26 + 7;
                if ( v28 < 0 )
                  v28 = v27;
                v71[4] = v28 >> 11;
                v7 = (v28 >> 3) + 2;
                v71[5] = v28 >> 3;
                sub_80FBA80(*(_DWORD *)(v24 + 20), v71 + 6);
                sub_81160B0(v24);
                goto LABEL_12;
              }
              sub_812B190(20, 152, 5, "s3_clnt.c", 2488);
            }
            else
            {
              sub_812B190(20, 152, 5, "s3_clnt.c", 2475);
            }
            sub_81160B0(v24);
          }
          else
          {
            sub_812B190(20, 152, 5, "s3_clnt.c", 2471);
          }
        }
        else
        {
          sub_80AAAA0(a1, 2, 40);
          sub_812B190(20, 152, 238, "s3_clnt.c", 2465);
        }
        goto LABEL_46;
      }
      sub_80AAAA0(a1, 2, 10);
      v55 = 2455;
    }
    else
    {
      if ( (v2 & 0xE0) == 0 )
      {
        if ( (v2 & 0x200) != 0 )
        {
          v36 = *(_DWORD *)(*(_DWORD *)(a1 + 192) + 152);
          v37 = *(_DWORD *)(v36 + 96);
          if ( v37 || (v37 = *(_DWORD *)(v36 + 84)) != 0 )
          {
            v63 = sub_81633B0(v37);
            v38 = sub_813AF50(v63, 0);
            v69 = v38;
            sub_813C030(v38);
            sub_8128870(v75, 32);
            if ( *(_DWORD *)(*(_DWORD *)(a1 + 88) + 856)
              && *(_DWORD *)(**(_DWORD **)(a1 + 152) + 4)
              && (int)sub_813C3D0(v38, *(_DWORD *)(**(_DWORD **)(a1 + 152) + 4)) <= 0 )
            {
              sub_812B270();
            }
            v39 = sub_812C6F0();
            v40 = sub_80D97F0(809);
            v41 = sub_81347F0(v40);
            sub_812C750(v39, v41);
            sub_812CC10(v39);
            sub_812CC10(v39);
            sub_812CC20(v39, s, v74);
            sub_812CEA0(v39);
            if ( (int)sub_813B6B0(v69, -1, 256, 8, 8, s) < 0 )
            {
              sub_812B190(20, 152, 274, "s3_clnt.c", 2763);
            }
            else
            {
              v73 = 255;
              v71[4] = 48;
              if ( (int)sub_813C0B0(v69, &src, &v73, v75, 32) >= 0 )
              {
                v42 = v73;
                if ( v73 <= 0x7F )
                {
                  v43 = v73;
                  desta = v71 + 6;
                  v7 = v73 + 2;
                }
                else
                {
                  v71[6] = v73;
                  v7 = v42 + 3;
                  v43 = -127;
                  desta = v71 + 7;
                }
                v71[5] = v43;
                memcpy(desta, &src, v42);
                if ( (int)sub_813B6B0(v69, -1, -1, 2, 2, 0) > 0 )
                  **(_DWORD **)(a1 + 88) |= 0x10u;
                sub_813B630(v69);
                v44 = *(_DWORD *)(a1 + 192);
                *(_DWORD *)(v44 + 16) = (*(int (__cdecl **)(int, int, char *, int))(*(_DWORD *)(*(_DWORD *)(a1 + 8) + 100)
                                                                                  + 12))(
                                          a1,
                                          v44 + 20,
                                          v75,
                                          32);
                sub_81368D0(v63);
                goto LABEL_12;
              }
              sub_812B190(20, 152, 274, "s3_clnt.c", 2775);
            }
          }
          else
          {
            sub_812B190(20, 152, 330, "s3_clnt.c", 2715);
          }
          goto LABEL_46;
        }
        v29 = *(_DWORD *)(*(_DWORD *)(*(_DWORD *)(a1 + 88) + 836) + 12) & 0x400;
        if ( (v2 & 0x400) == 0 )
        {
          if ( (v2 & 0x100) == 0 )
          {
            sub_80AAAA0(a1, 2, 40);
            sub_812B190(20, 152, 68, "s3_clnt.c", 2927);
            goto LABEL_46;
          }
          v46 = *(int (__cdecl **)(int, _DWORD, char *, int, char *, int))(a1 + 220);
          if ( !v46 )
          {
            sub_812B190(20, 152, 224, "s3_clnt.c", 2852);
            goto LABEL_46;
          }
          *(_WORD *)s = 0;
          memset32(&s[2], v29, 0x20u);
          v47 = v46(a1, *(_DWORD *)(*(_DWORD *)(a1 + 228) + 332), s, 129, &src, 516);
          if ( v47 > 0x100 )
          {
            sub_812B190(20, 152, 68, "s3_clnt.c", 2863);
          }
          else if ( v47 )
          {
            v70 = v47;
            HIBYTE(v77) = 0;
            v48 = strlen(s);
            if ( v48 <= 0x80 )
            {
              memmove(&src + v70 + 4, &src, v70);
              src = BYTE1(v70);
              v79 = v70;
              __memset_chk(v80, 0, v70, 514);
              v50 = &v80[v70];
              *v50 = BYTE1(v70);
              v51 = *(_DWORD *)(a1 + 192);
              v50[1] = v70;
              if ( *(_DWORD *)(v51 + 140) )
              {
                sub_80D5F10(*(void **)(v51 + 140));
                v51 = *(_DWORD *)(a1 + 192);
              }
              *(_DWORD *)(v51 + 140) = sub_811BEC0(*(char **)(*(_DWORD *)(a1 + 228) + 332));
              v52 = *(_DWORD *)(a1 + 192);
              if ( *(_DWORD *)(*(_DWORD *)(a1 + 228) + 332) && !*(_DWORD *)(v52 + 140) )
              {
                sub_812B190(20, 152, 65, "s3_clnt.c", 2893);
              }
              else
              {
                if ( *(_DWORD *)(v52 + 144) )
                {
                  sub_80D5F10(*(void **)(v52 + 144));
                  v52 = *(_DWORD *)(a1 + 192);
                }
                v64 = v52;
                v53 = sub_811BEC0(s);
                v54 = *(_DWORD *)(a1 + 192);
                *(_DWORD *)(v64 + 144) = v53;
                if ( *(_DWORD *)(v54 + 144) )
                {
                  *(_DWORD *)(v54 + 16) = (*(int (__cdecl **)(int, int, char *))(*(_DWORD *)(*(_DWORD *)(a1 + 8) + 100)
                                                                               + 12))(
                                            a1,
                                            v54 + 20,
                                            &src);
                  v71[4] = 0;
                  v71[5] = v48;
                  v56 = v48;
                  v7 = v48 + 2;
                  memcpy(v71 + 6, s, v56);
                  sub_80D8990(s, 0x82u);
                  sub_80D8990(&src, 0x204u);
                  goto LABEL_12;
                }
                sub_812B190(20, 152, 65, "s3_clnt.c", 2902);
              }
            }
            else
            {
              sub_812B190(20, 152, 68, "s3_clnt.c", 2874);
            }
          }
          else
          {
            sub_812B190(20, 152, 223, "s3_clnt.c", 2867);
          }
          sub_80D8990(s, 0x82u);
          sub_80D8990(&src, 0x204u);
          sub_80AAAA0(a1, 2, 40);
          goto LABEL_46;
        }
        if ( !*(_DWORD *)(a1 + 440) )
        {
          sub_812B190(20, 152, 68, "s3_clnt.c", 2813);
          goto LABEL_46;
        }
        v30 = sub_80FB010(*(_DWORD *)(a1 + 440));
        v31 = v30 + 14;
        v32 = v30 + 7;
        if ( v32 < 0 )
          v32 = v31;
        v71[4] = v32 >> 11;
        v7 = (v32 >> 3) + 2;
        v71[5] = v32 >> 3;
        sub_80FBA80(*(_DWORD *)(a1 + 440), v71 + 6);
        v33 = *(_DWORD *)(a1 + 192);
        if ( *(_DWORD *)(v33 + 240) )
        {
          sub_80D5F10(*(void **)(v33 + 240));
          v33 = *(_DWORD *)(a1 + 192);
        }
        *(_DWORD *)(v33 + 240) = sub_811BEC0(*(char **)(a1 + 420));
        v34 = *(_DWORD *)(a1 + 192);
        if ( !*(_DWORD *)(v34 + 240) )
        {
          sub_812B190(20, 152, 65, "s3_clnt.c", 2821);
          goto LABEL_46;
        }
        v35 = sub_80D4260(a1, v34 + 20);
        *(_DWORD *)(v34 + 16) = v35;
        if ( v35 < 0 )
        {
          sub_812B190(20, 152, 68, "s3_clnt.c", 2830);
          goto LABEL_46;
        }
LABEL_12:
        v71[1] = BYTE2(v7);
        *v71 = 16;
        v71[2] = BYTE1(v7);
        v71[3] = v7;
        *(_DWORD *)(a1 + 52) = 4481;
        *(_DWORD *)(a1 + 68) = v7 + 4;
        *(_DWORD *)(a1 + 72) = 0;
        return sub_80AB000(a1, 22);
      }
      v9 = *(_DWORD *)(*(_DWORD *)(a1 + 192) + 152);
      if ( v9 )
      {
        v10 = *(_DWORD *)(v9 + 116);
        dest = 0;
        if ( !v10 )
        {
          v49 = (_DWORD *)sub_81633B0(*(_DWORD *)(v9 + 72));
          dest = v49;
          if ( !v49 || *v49 != 408 || (v10 = v49[5]) == 0 )
          {
            sub_812B190(20, 152, 68, "s3_clnt.c", 2567);
            goto LABEL_47;
          }
        }
        v61 = sub_810C790(v10);
        v11 = sub_810C830(v10);
        if ( !v61 || !v11 )
        {
          sub_812B190(20, 152, 68, "s3_clnt.c", 2579);
          goto LABEL_47;
        }
        v66 = (void *)sub_810BBA0();
        if ( !v66 )
        {
          sub_812B190(20, 152, 65, "s3_clnt.c", 2585);
          goto LABEL_47;
        }
        if ( sub_810C7A0(v66, v61) )
        {
          if ( sub_810C0F0(v66) )
          {
            v12 = sub_8105E70(v61);
            if ( v12 <= 0 )
            {
              sub_812B190(20, 152, 43, "s3_clnt.c", 2626);
            }
            else
            {
              v13 = sub_81174C0(v1, (v12 + 7) >> 3, v11, v66, 0);
              if ( v13 > 0 )
              {
                v14 = *(_DWORD *)(a1 + 192);
                n = v13;
                *(_DWORD *)(v14 + 16) = (*(int (__cdecl **)(int, int, void *))(*(_DWORD *)(*(_DWORD *)(a1 + 8) + 100)
                                                                             + 12))(
                                          a1,
                                          v14 + 20,
                                          v1);
                memset(v1, 0, n);
                v15 = sub_810C830(v66);
                v16 = sub_810D8E0(v61, v15, 4, 0, 0, 0);
                v17 = (void *)sub_80D5BF0(v16, "s3_clnt.c", 2660);
                v18 = sub_80FC220();
                if ( v17 && v18 )
                {
                  na = v18;
                  v19 = sub_810C830(v66);
                  v20 = sub_810D8E0(v61, v19, 4, v17, v16, na);
                  v71[4] = v20;
                  v7 = v20 + 1;
                  memcpy(v71 + 5, v17, v20);
                  sub_80FC2B0(na);
                  sub_80D5F10(v17);
                  sub_810BD40(v66);
                  sub_81368D0(dest);
                  goto LABEL_12;
                }
                v72 = v18;
                sub_812B190(20, 152, 65, "s3_clnt.c", 2664);
                sub_80FC2B0(v72);
                if ( v17 )
                  sub_80D5F10(v17);
LABEL_95:
                sub_810BD40(v66);
                goto LABEL_48;
              }
              sub_812B190(20, 152, 43, "s3_clnt.c", 2632);
            }
          }
          else
          {
            sub_812B190(20, 152, 43, "s3_clnt.c", 2614);
          }
        }
        else
        {
          sub_812B190(20, 152, 16, "s3_clnt.c", 2590);
        }
        sub_80FC2B0(0);
        goto LABEL_95;
      }
      sub_80AAAA0(a1, 2, 10);
      v55 = 2524;
    }
    sub_812B190(20, 152, 244, "s3_clnt.c", v55);
    goto LABEL_46;
  }
  v3 = *(_DWORD *)(*(_DWORD *)(a1 + 192) + 152);
  if ( v3 )
  {
    v4 = *(_DWORD *)(v3 + 108);
    if ( v4 )
      goto LABEL_5;
    v45 = (_DWORD *)sub_81633B0(*(_DWORD *)(v3 + 12));
    if ( v45 )
    {
      if ( *v45 == 6 )
      {
        v4 = v45[5];
        if ( v4 )
        {
          sub_81368D0(v45);
LABEL_5:
          v5 = *(_DWORD *)(a1 + 272);
          src = HIBYTE(v5);
          v79 = v5;
          if ( (int)sub_8128870(v80, 46) > 0 )
          {
            *(_DWORD *)(*(_DWORD *)(a1 + 192) + 16) = 48;
            if ( *(int *)a1 >= 769 )
              v1 = v71 + 6;
            v6 = sub_8112560(48, &src, v1, v4);
            v7 = v6;
            if ( v6 > 0 )
            {
              if ( *(int *)a1 > 768 )
              {
                v71[4] = BYTE1(v6);
                v7 = v6 + 2;
                v71[5] = v6;
              }
              v65 = *(_DWORD *)(a1 + 192);
              *(_DWORD *)(v65 + 16) = (*(int (__cdecl **)(int, size_t, char *, int))(*(_DWORD *)(*(_DWORD *)(a1 + 8)
                                                                                               + 100)
                                                                                   + 12))(
                                        a1,
                                        v65 + 20,
                                        &src,
                                        48);
              sub_80D8990(&src, 0x30u);
              goto LABEL_12;
            }
            sub_812B190(20, 152, 119, "s3_clnt.c", 2299);
          }
          goto LABEL_46;
        }
      }
    }
    sub_812B190(20, 152, 68, "s3_clnt.c", 2271);
  }
  else
  {
    sub_812B190(20, 152, 68, "s3_clnt.c", 2257);
  }
LABEL_46:
  dest = 0;
LABEL_47:
  sub_80FC2B0(0);
LABEL_48:
  sub_81368D0(dest);
  return -1;
}