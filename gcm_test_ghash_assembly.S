.section        .rodata.cst16.POLY, "aM", @progbits, 16
.align 16
POLY:           .octa   0xC2000000000000000000000000000001

.section        .rodata.cst16.TWOONE, "aM", @progbits, 16
.align 16
TWOONE:         .octa   0x00000001000000000000000000000001

.section        .rodata.cst64.POLY2, "aM", @progbits, 64
.align 64
POLY2:          .octa   0xC20000000000000000000001C2000000
                .octa   0xC20000000000000000000001C2000000
                .octa   0xC20000000000000000000001C2000000
                .octa   0xC20000000000000000000001C2000000

.section        .rodata.cst64.SHUF_MASK, "aM", @progbits, 64
.align 64
SHUF_MASK:      .octa   0x000102030405060708090A0B0C0D0E0F
                .octa   0x000102030405060708090A0B0C0D0E0F
                .octa   0x000102030405060708090A0B0C0D0E0F
                .octa   0x000102030405060708090A0B0C0D0E0F

.text

#define STACK_GP_OFFSET         0
#define XMM_STORAGE             0
#define GP_STORAGE              (8*8)           //space for 7 GP registers + 1 for alignment
#define STACK_XMM_OFFSET        (STACK_GP_OFFSET + GP_STORAGE)
#define STACK_LOCAL_OFFSET      (STACK_XMM_OFFSET + XMM_STORAGE)
#define LOCAL_STORAGE           (48*16)        //space for up to 128 AES blocks
#define STACK_FRAME_SIZE        (STACK_LOCAL_OFFSET + LOCAL_STORAGE)

#define KEY             %rdi
#define EXP_ENC_KEYS    %rsi
#define EXP_DEC_KEYS    %rdx
#define max_hkey_idx	48
#define HashKey_48      (16*15)
#define HashKey_47      (16*16)
#define HashKey_46      (16*17)
#define HashKey_45      (16*18)
#define HashKey_44      (16*19)
#define HashKey_43      (16*20)
#define HashKey_42      (16*21)
#define HashKey_41      (16*22)
#define HashKey_40      (16*23)
#define HashKey_39      (16*24)
#define HashKey_38      (16*25)
#define HashKey_37      (16*26)
#define HashKey_36      (16*27)
#define HashKey_35      (16*28)
#define HashKey_34      (16*29)
#define HashKey_33      (16*30)
#define HashKey_32      (16*31)
#define HashKey_31      (16*32)
#define HashKey_30      (16*33)
#define HashKey_29      (16*34)
#define HashKey_28      (16*35)
#define HashKey_27      (16*36)
#define HashKey_26      (16*37)
#define HashKey_25      (16*38)
#define HashKey_24      (16*39)
#define HashKey_23      (16*40)
#define HashKey_22      (16*41)
#define HashKey_21      (16*42)
#define HashKey_20      (16*43)
#define HashKey_19      (16*44)
#define HashKey_18      (16*45)
#define HashKey_17      (16*46)
#define HashKey_16      (16*47)
#define HashKey_15      (16*48)
#define HashKey_14      (16*49)
#define HashKey_13      (16*50)
#define HashKey_12      (16*51)
#define HashKey_11      (16*52)
#define HashKey_10      (16*53)
#define HashKey_9       (16*54)
#define HashKey_8       (16*55)
#define HashKey_7       (16*56)
#define HashKey_6       (16*57)
#define HashKey_5       (16*58)
#define HashKey_4       (16*59)
#define HashKey_3       (16*60)
#define HashKey_2       (16*61)
#define HashKey_1       (16*62)
#define HashKey         (16*62)

#define xmm5y ymm5
#define xmm5x xmm5
#define ymm5x xmm5
#define ymm5y ymm5
#define xmm0z zmm0
#define zmm17x xmm17
#define zmm19x xmm19
#define zmm20x xmm20
#define zmm21x xmm21
#define zmm17y ymm17
#define zmm19y ymm19
#define xmm14x xmm14
#define zmm20y ymm20
#define zmm21y ymm21
#define zmm30x xmm30
#define zmm31x xmm31
#define zmm30y ymm30
#define zmm31y ymm31
#define xmm9y ymm9
#define zmm29y ymm29
#define xmm9z zmm9
#define zmm1x xmm1
#define zmm1y ymm1
#define zmm4y ymm4
#define zmm8x xmm8
#define zmm4x xmm4
#define zmm3x xmm3
#define zmm2x xmm2
#define zmm1x xmm1
#define zmm0x xmm0
#define xmm14z zmm14
#define zmm3y ymm3
#define zmm2y ymm2
#define zmm0y ymm0
#define zmm7x xmm7
#define zmm5x xmm5
#define zmm6x xmm6
#define zmm7y ymm7
#define zmm5y ymm5
#define zmm6y ymm6
#define zmm15y ymm15
#define zmm16y ymm16
#define zmm29x xmm29
#define zmm11x xmm11
#define zmm28x xmm28
#define zmm9y ymm9
#define zmm9x xmm9
#define ymm4y ymm4
#define ymm3y ymm3
#define ymm2y ymm2
#define ymm1y ymm1
#define ymm4x xmm4
#define ymm3x xmm3
#define xmm4y ymm4
#define xmm3y ymm3
#define xmm2y ymm2
#define xmm1y ymm1
#define xmm4x xmm4
#define xmm3x xmm3
#define ymm1x xmm1
#define ymm2x xmm2
#define xmm1x xmm1
#define xmm2x xmm2
#define zmm8y ymm8
#define zmm10y ymm10
#define zmm10x xmm10
#define zmm12y ymm12
#define zmm13y ymm13
#define zmm13x xmm13
#define zmm15x xmm15
#define zmm16x xmm16
#define zmm12x xmm12
#define zmm6x xmm6

#define str(reg,y)	reg##y
#define str2(reg,y)	str(reg,y)
#define str1(reg,y)	str2(reg,y)
#define YWORD(reg)	str1(reg, y)
#define XWORD(reg)	str1(reg, x)
#define ZWORD(reg)	str1(reg, z)
#define DWORD(reg)	str1(reg, d)
#define WORD(reg)	str1(reg, w)
#define BYTE(reg)	str1(reg, b)

#define FUNC_SAVE()                                     \
        mov     %rsp, %rax;                             \
        sub     $STACK_FRAME_SIZE, %rsp;                \
        and     $~63, %rsp;                             \
        mov     %r12, STACK_GP_OFFSET + 0*8 (%rsp);     \
        mov     %r13, STACK_GP_OFFSET + 1*8 (%rsp);     \
        mov     %r14, STACK_GP_OFFSET + 2*8 (%rsp);     \
        mov     %r15, STACK_GP_OFFSET + 3*8 (%rsp);     \
        mov     %rax, STACK_GP_OFFSET + 4*8 (%rsp);     \
        mov     %rax, %r14;                             \
        mov     %rbp, STACK_GP_OFFSET + 5*8 (%rsp);     \
        mov     %rbx, STACK_GP_OFFSET + 6*8 (%rsp);

#define FUNC_RESTORE()                                  \
        vzeroupper;                                     \
        mov     STACK_GP_OFFSET + 5*8(%rsp), %rbp;      \
        mov     STACK_GP_OFFSET + 6*8(%rsp), %rbx;      \
        mov     STACK_GP_OFFSET + 0*8(%rsp), %r12;      \
        mov     STACK_GP_OFFSET + 1*8(%rsp), %r13;      \
        mov     STACK_GP_OFFSET + 2*8(%rsp), %r14;      \
        mov     STACK_GP_OFFSET + 3*8(%rsp), %r15;      \
        mov     STACK_GP_OFFSET + 4*8(%rsp), %rsp;

#define key_expansion_128_avx				\
        vpshufd $0xff, %xmm2, %xmm2;			\
        vshufps $0x10, %xmm1, %xmm3, %xmm3;		\
        vpxor   %xmm3, %xmm1, %xmm1;			\
        vshufps $0x8c, %xmm1, %xmm3, %xmm3;		\
        vpxor   %xmm3, %xmm1, %xmm1;			\
        vpxor   %xmm2, %xmm1, %xmm1;			

#define ENCRYPT_SINGLE_BLOCK(GDATA, XMM0)       \
        vpxorq (GDATA), XMM0, XMM0;             \
        vaesenc 16*1(GDATA), XMM0, XMM0;        \
        vaesenc 16*2(GDATA), XMM0, XMM0;        \
        vaesenc 16*3(GDATA), XMM0, XMM0;        \
        vaesenc 16*4(GDATA), XMM0, XMM0;        \
        vaesenc 16*5(GDATA), XMM0, XMM0;        \
        vaesenc 16*6(GDATA), XMM0, XMM0;        \
        vaesenc 16*7(GDATA), XMM0, XMM0;        \
        vaesenc 16*8(GDATA), XMM0, XMM0;        \
        vaesenc 16*9(GDATA), XMM0, XMM0;        \
        vaesenclast 16*10(GDATA), XMM0, XMM0;   \

#define GHASH_MUL(GH, HK, T1, T2, T3, T4, T5)                   \
        vpclmulqdq      $0x11, HK, GH, T1;                      \
        vpclmulqdq      $0x00, HK, GH, T2;                      \
        vpclmulqdq      $0x01, HK, GH, T3;                      \
        vpclmulqdq      $0x10, HK, GH, GH;                      \
        vpxorq          T3, GH, GH;                             \
        vpsrldq         $8, GH, T3;                             \
        vpslldq         $8, GH, GH;                             \
        vpxorq          T3, T1, T1;                             \
        vpxorq          T2, GH, GH;                             \
        vmovdqu64       POLY2(%rip), T3;                        \
        vpclmulqdq      $0x01, GH, T3, T2;                      \
        vpslldq         $8, T2, T2;                             \
        vpxorq          T2, GH, GH;                             \
        vpclmulqdq      $0x00, GH, T3, T2;                      \
        vpsrldq         $4, T2, T2;                             \
        vpclmulqdq      $0x10, GH, T3, GH;                      \
        vpslldq         $4, GH, GH;                             \
        vpternlogq      $0x96, T2, T1, GH;

#define PRECOMPUTE(GDATA, HK, T1, T2, T3, T4, T5, T6)   \
        vmovdqa HK, T5;         \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_2(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_3(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_4(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_5(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_6(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_7(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_8(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_9(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_10(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_11(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_12(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_13(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_14(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_15(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_16(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_17(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_18(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_19(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_20(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_21(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_22(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_23(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_24(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_25(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_26(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_27(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_28(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_29(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_30(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_31(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_32(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_33(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_34(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_35(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_36(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_37(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_38(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_39(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_40(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_41(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_42(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_43(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_44(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_45(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_46(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_47(GDATA);           \
        GHASH_MUL(T5, HK, T1, T3, T4, T6, T2)   \
        vmovdqu T5, HashKey_48(GDATA);           \

#define simd_store_avx(DST, SRC, SIZE, TMP, IDX)	\
	xor IDX, IDX;		\
	test	$16, SIZE;	\
	jz	lt16;		\
	vmovdqu	SRC, (DST);	\
	jmp	end;		\
lt16:;	\
	test	$8, SIZE;       \
	jz      lt8;           	\
	vmovq	SRC, (DST, IDX, 1);	\
	vpsrldq	$8, SRC, SRC;	\
	add	$8, IDX;	\
lt8:;	\
	vmovq 	SRC, TMP;	\
	test	$4, SIZE;       \
        jz      lt4;            \
	mov	DWORD(TMP), (DST, IDX, 1);	\
	shr	$32, TMP;	\
	add	$4, IDX;	\
lt4:;	\
	test	$2, SIZE;       \
        jz      lt2;            \
        mov     WORD(TMP), (DST, IDX, 1);   \
        shr     $16, TMP;       \
        add     $2, IDX;        \
lt2:;\
	test	$1, SIZE;          \
	jz end;	\
	mov	BYTE(TMP), (DST, IDX, 1);	\
end:;

#define VCLMUL_STEP1(KP, HI, TMP, TH, TM, TL, HKEY, NP) \
        .if NP == 6;                                    \
        vmovdqu64       HashKey_4(KP) , TMP;            \
        .else;                                          \
        vmovdqa64       HKEY, TMP;                      \
        .endif;                                         \
        vpclmulqdq      $0x11, TMP, HI, TH;             \
        vpclmulqdq      $0x00, TMP, HI, TL;             \
        vpclmulqdq      $0x01, TMP, HI, TM;             \
        vpclmulqdq      $0x10, TMP, HI, TMP;            \
        vpxorq          TMP, TM, TM;

#define VHPXORI4x128(REG,TMP)                                   \
        vextracti64x4   $1, REG, YWORD(TMP);                    \
        vpxorq          YWORD(TMP), YWORD(REG), YWORD(REG);     \
        vextracti32x4   $1, YWORD(REG), XWORD(TMP);             \
        vpxorq          XWORD(TMP), XWORD(REG), XWORD(REG);

#define VHPXORI2x128(REG, TMP)                                  \
        vextracti32x4   $1, REG, XWORD(TMP);                    \
        vpxorq          XWORD(TMP), XWORD(REG), XWORD(REG);

#define VCLMUL_STEP2(KP, HI, LO, TMP0, TMP1, TMP2, TH, TM, TL, HKEY, HXOR, NP)  \
        .if NP == 9;                                            \
        vmovdqu64       HashKey_8(KP), TMP0;                    \
        .else;                                                  \
        vmovdqa64       HKEY, TMP0;                             \
        .endif;                                                 \
        vpclmulqdq      $0x10, TMP0, LO, TMP1;                  \
        vpclmulqdq      $0x11, TMP0, LO, TMP2;                  \
        vpxorq          TMP2, TH, TH;                           \
        vpclmulqdq      $0x00, TMP0, LO, TMP2;                  \
        vpxorq          TMP2, TL, TL;                           \
        vpclmulqdq      $0x01, TMP0, LO, TMP0;                  \
        vpternlogq      $0x96, TMP0, TMP1, TM;                  \
        vpsrldq         $8, TM, TMP2;                           \
        vpxorq          TMP2, TH, HI;                           \
        vpslldq         $8, TM, TMP2;                           \
        vpxorq          TMP2, TL, LO;                           \
        .if NP < 11;                                            \
        VHPXORI4x128(HI, TMP2)                                  \
        VHPXORI4x128(LO, TMP1)                                  \
        .elseif HXOR == 4;                                      \
        VHPXORI4x128(HI, TMP2)                                  \
        VHPXORI4x128(LO, TMP1)                                  \
        .elseif HXOR == 2;                                      \
        VHPXORI2x128(HI, TMP2)                                  \
        VHPXORI2x128(LO, TMP1)                                  \
        .endif;

#define VCLMUL_REDUCE(OUT, POLY, HI128, LO128, TMP0, TMP1)      \
        vpclmulqdq      $0x01, LO128, POLY, TMP0;               \
        vpslldq         $8, TMP0, TMP0;                         \
        vpxorq          TMP0, LO128, TMP0;                      \
        vpclmulqdq      $0x00, TMP0, POLY, TMP1;                \
        vpsrldq         $4, TMP1, TMP1;                         \
        vpclmulqdq      $0x10, TMP0, POLY, OUT;                 \
        vpslldq         $4, OUT, OUT;                           \
        vpternlogq      $0x96, HI128, TMP1, OUT;

#define VCLMUL_1_TO_8_STEP1(KP, HI, TMP1, TMP2, TH, TM, TL, NBLOCKS)    \
        .if NBLOCKS == 8;                                               \
                VCLMUL_STEP1(KP, HI, TMP1, TH, TM, TL, NULL, 6)         \
        .elseif NBLOCKS == 7;                                           \
                vmovdqu64       HashKey_3(KP), TMP2;                    \
                vmovdqa64      (%rip), TMP1;                            \
                vpandq          TMP1, TMP2, TMP2;                             \
                vpandq          TMP1, HI, HI;                               \
                VCLMUL_STEP1(NULL, HI, TMP1, TH, TM, TL, TMP2, 7)       \
        .elseif NBLOCKS == 6;                                           \
                vmovdqu64       HashKey_2(KP), YWORD(TMP2);             \
                VCLMUL_STEP1(NULL, YWORD(HI), YWORD(TMP1), YWORD(TH), YWORD(TM), YWORD(TL), YWORD(TMP2), 7)     \
        .elseif NBLOCKS == 5;                                   \
                vmovdqu64       HashKey_1(KP), XWORD(TMP2);     \
                VCLMUL_STEP1(NULL, XWORD(HI), XWORD(TMP1), XWORD(TH), XWORD(TM), XWORD(TL), XWORD(TMP2), 7)     \
        .else;                                                   \
                vpxorq          TH, TH, TH;                     \
                vpxorq          TM, TM, TM;                     \
                vpxorq          TL, TL, TL;                     \
        .endif;

#define VCLMUL_1_TO_8_STEP2(KP, HI, LO, TMP0, TMP1, TMP2, TH, TM, TL, NBLOCKS)  \
        .if NBLOCKS == 8;                                                       \
                VCLMUL_STEP2(KP, HI, LO, TMP0, TMP1, TMP2, TH, TM, TL, NULL, NULL, 9)           \
        .elseif NBLOCKS == 7;                                                   \
                vmovdqu64       HashKey_7(KP), TMP2;                            \
                VCLMUL_STEP2(NULL, HI, LO, TMP0, TMP1, TMP2, TH, TM, TL, TMP2, 4, 11)   \
        .elseif NBLOCKS == 6;                                                   \
                vmovdqu64       HashKey_6(KP), TMP2;                            \
                VCLMUL_STEP2(NULL, HI, LO, TMP0, TMP1, TMP2, TH, TM, TL, TMP2, 4, 11)   \
        .elseif NBLOCKS == 5;                                                   \
                vmovdqu64       HashKey_5(KP), TMP2;                            \
                VCLMUL_STEP2(NULL, HI, LO, TMP0, TMP1, TMP2, TH, TM, TL, TMP2, 4, 11)   \
        .elseif NBLOCKS == 4;                                                   \
                vmovdqu64       HashKey_4(KP), TMP2;                            \
                VCLMUL_STEP2(NULL, HI, LO, TMP0, TMP1, TMP2, TH, TM, TL, TMP2, 4, 11)   \
        .elseif NBLOCKS == 3;                                                   \
                vmovdqu64       HashKey_3(KP), TMP2;                            \
                vmovdqa64       (%rip), TMP1;                                   \
                vpandq          TMP1, TMP2, TMP2;                                       \
                vpandq          TMP1, LO, LO;                                   \
                VCLMUL_STEP2(NULL, HI, LO, TMP0, TMP1, TMP2, TH, TM, TL, TMP2, 4, 11)   \
        .elseif NBLOCKS == 2;                                                   \
                vmovdqu64       HashKey_2(KP), YWORD(TMP2);                     \
                VCLMUL_STEP2(NULL, YWORD(HI), YWORD(LO), YWORD(TMP0), YWORD(TMP1), YWORD(TMP2), YWORD(TH), YWORD(TM), YWORD(TL), YWORD(TMP2), 2, 11)            \
        .elseif NBLOCKS == 1;                           \
                vmovdqu64       HashKey_1(KP), XWORD(TMP2);                     \
                VCLMUL_STEP2(NULL, XWORD(HI), XWORD(LO), XWORD(TMP0), XWORD(TMP1), XWORD(TMP2), XWORD(TH), XWORD(TM), XWORD(TL), XWORD(TMP2), 1, 11)            \
        .else;                                          \
                vpxorq          HI, HI, HI;             \
                vpxorq          LO, LO, LO;             \
        .endif;

#define CALC_AAD_HASH(A_IN, A_LEN, AAD_HASH, GDATA_KEY, ZT0, ZT1, ZT2, ZT3, ZT4, TL, TM, TH, POLY, SHFMSK, T1, T2, T3, MASKREG) \
        mov             A_IN, T1;                       \
        mov             A_LEN, T2;                      \
        vpxorq          AAD_HASH, AAD_HASH, AAD_HASH;   \
        vmovdqa64       SHUF_MASK(%rip), SHFMSK;        \
        vmovdqa64       POLY2(%rip), POLY;              \
_get_AAD_loop128:;                                      \
        cmp             $128, T2;                       \
        jl              _exit_AAD_loop128;              \
        vmovdqu64       64*0(T1), ZT2;                  \
        vmovdqu64       64*1(T1), ZT1;                  \
        vpshufb         SHFMSK, ZT2, ZT2;               \
        vpshufb         SHFMSK, ZT1, ZT1;               \
        vpxorq          ZWORD(AAD_HASH), ZT2, ZT2;      \
        \
        VCLMUL_STEP1(GDATA_KEY, ZT1, ZT0, TH, TM, TL, NULL, 6)   \
        VCLMUL_STEP2(GDATA_KEY, ZT1, ZT2, ZT0, ZT3, ZT4, TH, TM, TL, NULL, NULL, 9)    \
        VCLMUL_REDUCE(AAD_HASH, XWORD(POLY), XWORD(ZT1), XWORD(ZT2), XWORD(ZT0), XWORD(ZT3))    \
        \
        sub             $128, T2;                       \
        je              _CALC_AAD_done;                 \
        add             $128, T1;                       \
        jmp             _get_AAD_loop128;               \
        \
_exit_AAD_loop128:;                             \
        or              T2, T2;                 \
        jz              _CALC_AAD_done;         \
        lea             (%rip), T3;             \
        lea             (T3, T2, 8), T3;        \
        add             $15, T2;                \
        and             $-16, T2;               \
        shr             $4, T2;                 \
        cmp             $7, T2;                 \
        je              _AAD_blocks_7;          \
        cmp             $6, T2;         \
        je              _AAD_blocks_6;          \
        cmp             $5, T2;         \
        je              _AAD_blocks_5;          \
        cmp             $4, T2;         \
        je              _AAD_blocks_4;          \
        cmp             $3, T2;         \
        je              _AAD_blocks_3;          \
        cmp             $2, T2;         \
        je              _AAD_blocks_2;          \
        cmp             $1, T2;         \
        je              _AAD_blocks_1;          \
        \
_AAD_blocks_8:;                                         \
        sub             $512, T3;                       \
        kmovq           (T3), MASKREG;                  \
        vmovdqu8        (T1), ZT2;                      \
        vmovdqu8        64(T1), ZT1{MASKREG}{z};        \
        vpshufb         SHFMSK, ZT2, ZT2;               \
        vpshufb         SHFMSK, ZT1, ZT1;               \
        vpxorq          ZWORD(AAD_HASH), ZT2, ZT2;      \
        VCLMUL_1_TO_8_STEP1(GDATA_KEY, ZT1, ZT0, ZT3, TH, TM, TL, 8)    \
        VCLMUL_1_TO_8_STEP2(GDATA_KEY, ZT1, ZT2, ZT0, ZT3, ZT4, TH, TM, TL, 8)  \
        jmp             _AAD_blocks_done;               \
_AAD_blocks_7:;                                         \
        sub             $512, T3;                       \
        kmovq           (T3), MASKREG;                  \
        vmovdqu8        (T1), ZT2;                      \
        vmovdqu8        64(T1), ZT1{MASKREG}{z};        \
        vpshufb         SHFMSK, ZT2, ZT2;               \
        vpshufb         SHFMSK, ZT1, ZT1;               \
        vpxorq          ZWORD(AAD_HASH), ZT2, ZT2;      \
        VCLMUL_1_TO_8_STEP1(GDATA_KEY, ZT1, ZT0, ZT3, TH, TM, TL, 7)    \
        VCLMUL_1_TO_8_STEP2(GDATA_KEY, ZT1, ZT2, ZT0, ZT3, ZT4, TH, TM, TL, 7)  \
        jmp             _AAD_blocks_done;               \
_AAD_blocks_6:;                                         \
        sub             $512, T3;                       \
        kmovq           (T3), MASKREG;                  \
        vmovdqu8        (T1), ZT2;                      \
        vmovdqu8        64(T1), YWORD(ZT1){MASKREG}{z};        \
        vpshufb         SHFMSK, ZT2, ZT2;               \
        vpshufb         YWORD(SHFMSK), YWORD(ZT1), YWORD(ZT1);               \
        vpxorq          ZWORD(AAD_HASH), ZT2, ZT2;      \
        VCLMUL_1_TO_8_STEP1(GDATA_KEY, ZT1, ZT0, ZT3, TH, TM, TL, 6)    \
        VCLMUL_1_TO_8_STEP2(GDATA_KEY, ZT1, ZT2, ZT0, ZT3, ZT4, TH, TM, TL, 6)  \
        jmp             _AAD_blocks_done;               \
_AAD_blocks_5:;                                         \
        sub             $512, T3;                       \
        kmovq           (T3), MASKREG;                  \
        vmovdqu8        (T1), ZT2;                      \
        vmovdqu8        64(T1), XWORD(ZT1){MASKREG}{z};        \
        vpshufb         SHFMSK, ZT2, ZT2;               \
        vpshufb         XWORD(SHFMSK), XWORD(ZT1), XWORD(ZT1);               \
        vpxorq          ZWORD(AAD_HASH), ZT2, ZT2;      \
        VCLMUL_1_TO_8_STEP1(GDATA_KEY, ZT1, ZT0, ZT3, TH, TM, TL, 5)    \
        VCLMUL_1_TO_8_STEP2(GDATA_KEY, ZT1, ZT2, ZT0, ZT3, ZT4, TH, TM, TL, 5)  \
        jmp             _AAD_blocks_done;               \
_AAD_blocks_4:;                                         \
        kmovq           (T3), MASKREG;                  \
        vmovdqu8        (T1), ZT2{MASKREG}{z};          \
        vpshufb         SHFMSK, ZT2, ZT2;               \
        vpxorq          ZWORD(AAD_HASH), ZT2, ZT2;      \
        VCLMUL_1_TO_8_STEP1(GDATA_KEY, ZT1, ZT0, ZT3, TH, TM, TL, 4)    \
        VCLMUL_1_TO_8_STEP2(GDATA_KEY, ZT1, ZT2, ZT0, ZT3, ZT4, TH, TM, TL, 4)  \
        jmp             _AAD_blocks_done;               \
_AAD_blocks_3:;                                         \
        kmovq           (T3), MASKREG;                  \
        vmovdqu8        (T1), ZT2{MASKREG}{z};          \
        vpshufb         SHFMSK, ZT2, ZT2;               \
        vpxorq          ZWORD(AAD_HASH), ZT2, ZT2;      \
        VCLMUL_1_TO_8_STEP1(GDATA_KEY, ZT1, ZT0, ZT3, TH, TM, TL, 3)    \
        VCLMUL_1_TO_8_STEP2(GDATA_KEY, ZT1, ZT2, ZT0, ZT3, ZT4, TH, TM, TL, 3)  \
        jmp             _AAD_blocks_done;               \
_AAD_blocks_2:;                                         \
        kmovq           (T3), MASKREG;                  \
        vmovdqu8        (T1), YWORD(ZT2){MASKREG}{z};          \
        vpshufb         YWORD(SHFMSK), YWORD(ZT2), YWORD(ZT2);               \
        vpxorq          ZWORD(AAD_HASH), ZT2, ZT2;      \
        VCLMUL_1_TO_8_STEP1(GDATA_KEY, ZT1, ZT0, ZT3, TH, TM, TL, 2)    \
	VCLMUL_1_TO_8_STEP2(GDATA_KEY, ZT1, ZT2, ZT0, ZT3, ZT4, TH, TM, TL, 2)  \
        jmp             _AAD_blocks_done;               \
_AAD_blocks_1:;                                         \
        kmovq           (T3), MASKREG;                  \
        vmovdqu8        (T1), XWORD(ZT2){MASKREG}{z};          \
        vpshufb         XWORD(SHFMSK), XWORD(ZT2), XWORD(ZT2);               \
        vpxorq          ZWORD(AAD_HASH), ZT2, ZT2;      \
        VCLMUL_1_TO_8_STEP1(GDATA_KEY, ZT1, ZT0, ZT3, TH, TM, TL, 1)    \
        VCLMUL_1_TO_8_STEP2(GDATA_KEY, ZT1, ZT2, ZT0, ZT3, ZT4, TH, TM, TL, 1)  \
_AAD_blocks_done:;                                      \
        VCLMUL_REDUCE(AAD_HASH, XWORD(POLY), XWORD(ZT1), XWORD(ZT2), XWORD(ZT0), XWORD(ZT3))    \
_CALC_AAD_done:;

.global aes_keyexp_128_enc_vaes_avx512

aes_keyexp_128_enc_vaes_avx512:
	vmovdqu	(KEY), %xmm1
	vmovdqa	%xmm1, (EXP_ENC_KEYS)
	vpxor   %xmm3, %xmm3, %xmm3

	vaeskeygenassist	$0x1, %xmm1, %xmm2
	key_expansion_128_avx
	vmovdqa %xmm1, 16*1(EXP_ENC_KEYS)

	vaeskeygenassist        $0x2, %xmm1, %xmm2
        key_expansion_128_avx
        vmovdqa %xmm1, 16*2(EXP_ENC_KEYS)

	vaeskeygenassist        $0x4, %xmm1, %xmm2
        key_expansion_128_avx
        vmovdqa %xmm1, 16*3(EXP_ENC_KEYS)

	vaeskeygenassist        $0x8, %xmm1, %xmm2
        key_expansion_128_avx
        vmovdqa %xmm1, 16*4(EXP_ENC_KEYS)

	vaeskeygenassist        $0x10, %xmm1, %xmm2
        key_expansion_128_avx
        vmovdqa %xmm1, 16*5(EXP_ENC_KEYS)

	vaeskeygenassist        $0x20, %xmm1, %xmm2
        key_expansion_128_avx
        vmovdqa %xmm1, 16*6(EXP_ENC_KEYS)

	vaeskeygenassist        $0x40, %xmm1, %xmm2
        key_expansion_128_avx
        vmovdqa %xmm1, 16*7(EXP_ENC_KEYS)

	vaeskeygenassist        $0x80, %xmm1, %xmm2
        key_expansion_128_avx
        vmovdqa %xmm1, 16*8(EXP_ENC_KEYS)

	vaeskeygenassist        $0x1b, %xmm1, %xmm2
        key_expansion_128_avx
        vmovdqa %xmm1, 16*9(EXP_ENC_KEYS)

	vaeskeygenassist        $0x36, %xmm1, %xmm2
        key_expansion_128_avx
        vmovdqa %xmm1, 16*10(EXP_ENC_KEYS)

aes_keyexp_128_enc_avx_return:
        ret

.global aes_gcm_precomp_128_vaes_avx512

aes_gcm_precomp_128_vaes_avx512:
	FUNC_SAVE()
	vpxor   %xmm6, %xmm6, %xmm6
	ENCRYPT_SINGLE_BLOCK(%rdi, %xmm6)

	vpshufb SHUF_MASK(%rip), %xmm6, %xmm6
	vmovdqa %xmm6, %xmm2
	vpsllq  $1, %xmm6, %xmm6
        vpsrlq  $63, %xmm2, %xmm2
        vmovdqa %xmm2, %xmm1
        vpslldq $8, %xmm2, %xmm2
        vpsrldq $8, %xmm1, %xmm1
        vpor    %xmm2, %xmm6, %xmm6

	vpshufd  $0x24, %xmm1, %xmm2
        vpcmpeqd TWOONE(%rip), %xmm2, %xmm2
        vpand    POLY(%rip), %xmm2, %xmm2
        vpxor    %xmm2, %xmm6, %xmm6

	vmovdqu  %xmm6, HashKey(%rdi)

	PRECOMPUTE(%rdi, %xmm6, %xmm0, %xmm1, %xmm2, %xmm3, %xmm4, %xmm5)

	FUNC_RESTORE() 
exit_precomp:
	ret

.global ghash_vaes_avx512

ghash_vaes_avx512:
	FUNC_SAVE()

	CALC_AAD_HASH(%rsi, %rdx, %xmm0, %rdi, %zmm1, %zmm2, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm8, %zmm9, %zmm10, %r10, %r11, %r12, %k1)

        vpshufb SHUF_MASK(%rip), %xmm0, %xmm0

        simd_store_avx(%rcx, %xmm0, %r8, %r12, %rax)

exit_ghash:
        FUNC_RESTORE()

        ret

