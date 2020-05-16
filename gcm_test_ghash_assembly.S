.data

.align 16
POLY:		.octa   0xC2000000000000000000000000000001

.align 64
POLY2:		.octa   0xC20000000000000000000001C2000000
		.octa   0xC20000000000000000000001C2000000
		.octa   0xC20000000000000000000001C2000000
		.octa   0xC20000000000000000000001C2000000

.align 16
TWOONE:
		.octa	0x00000001000000000000000000000001

.align 64
SHUF_MASK:	.octa   0x000102030405060708090A0B0C0D0E0F
		.octa   0x000102030405060708090A0B0C0D0E0F
		.octa   0x000102030405060708090A0B0C0D0E0F
		.octa   0x000102030405060708090A0B0C0D0E0F

.align 16
SHIFT_MASK:      .octa     0x0f0e0d0c0b0a09080706050403020100
ALL_F:           .octa     0xffffffffffffffffffffffffffffffff
ZERO:            .octa     0x00000000000000000000000000000000

.align 16
ONE:
.octa   0x00000000000000000000000000000001

.align 16
ONEf:
.octa   0x01000000000000000000000000000000

.align 64
ddq_add_1234:
.octa   0x00000000000000000000000000000001
.octa   0x00000000000000000000000000000002
.octa   0x00000000000000000000000000000003
.octa   0x00000000000000000000000000000004

.align 64
ddq_add_5678:
.octa   0x00000000000000000000000000000005
.octa   0x00000000000000000000000000000006
.octa   0x00000000000000000000000000000007
.octa   0x00000000000000000000000000000008

.align 64
ddq_add_4444:
.octa   0x00000000000000000000000000000004
.octa   0x00000000000000000000000000000004
.octa   0x00000000000000000000000000000004
.octa   0x00000000000000000000000000000004

.align 64
ddq_add_8888:
.octa   0x00000000000000000000000000000008
.octa   0x00000000000000000000000000000008
.octa   0x00000000000000000000000000000008
.octa   0x00000000000000000000000000000008

.align 64
ddq_addbe_1234:
.octa   0x01000000000000000000000000000000
.octa   0x02000000000000000000000000000000
.octa   0x03000000000000000000000000000000
.octa   0x04000000000000000000000000000000

.align 64
ddq_addbe_4444:
.octa   0x04000000000000000000000000000000
.octa   0x04000000000000000000000000000000
.octa   0x04000000000000000000000000000000
.octa   0x04000000000000000000000000000000

.align 64
ddq_addbe_8888:
.octa   0x08000000000000000000000000000000
.octa   0x08000000000000000000000000000000
.octa   0x08000000000000000000000000000000
.octa   0x08000000000000000000000000000000

.align 64
byte_len_to_mask_table:
.quad   0x0007000300010000
.quad   0x007f003f001f000f
.quad   0x07ff03ff01ff00ff
.quad   0x7fff3fff1fff0fff
.quad   0xffff

.align 64
byte64_len_to_mask_table:
.octa	0x00000000000000010000000000000000
.octa	0x00000000000000070000000000000003
.octa	0x000000000000001f000000000000000f
.octa	0x000000000000007f000000000000003f
.octa	0x00000000000001ff00000000000000ff
.octa	0x00000000000007ff00000000000003ff
.octa	0x0000000000001fff0000000000000fff
.octa	0x0000000000007fff0000000000003fff
.octa	0x000000000001ffff000000000000ffff
.octa	0x000000000007ffff000000000003ffff
.octa	0x00000000001fffff00000000000fffff
.octa	0x00000000007fffff00000000003fffff
.octa	0x0000000001ffffff0000000000ffffff
.octa	0x0000000007ffffff0000000003ffffff
.octa	0x000000001fffffff000000000fffffff
.octa	0x000000007fffffff000000003fffffff
.octa	0x00000001ffffffff00000000ffffffff
.octa	0x00000007ffffffff00000003ffffffff
.octa	0x0000001fffffffff0000000fffffffff
.octa	0x0000007fffffffff0000003fffffffff
.octa	0x000001ffffffffff000000ffffffffff
.octa	0x000007ffffffffff000003ffffffffff
.octa	0x00001fffffffffff00000fffffffffff
.octa	0x00007fffffffffff00003fffffffffff
.octa	0x0001ffffffffffff0000ffffffffffff
.octa	0x0007ffffffffffff0003ffffffffffff
.octa	0x001fffffffffffff000fffffffffffff
.octa	0x007fffffffffffff003fffffffffffff
.octa	0x01ffffffffffffff00ffffffffffffff
.octa	0x07ffffffffffffff03ffffffffffffff
.octa	0x1fffffffffffffff0fffffffffffffff
.octa	0x7fffffffffffffff3fffffffffffffff
.octa	0xffffffffffffffff

.align 64
mask_out_top_block:
.octa   0xffffffffffffffffffffffffffffffff
.octa   0xffffffffffffffffffffffffffffffff
.octa   0xffffffffffffffffffffffffffffffff
.octa   0x00000000000000000000000000000000

.text

#define STACK_GP_OFFSET         0
#define XMM_STORAGE             0
#define GP_STORAGE              (8*8)           //space for 7 GP registers + 1 for alignment
#define STACK_XMM_OFFSET	64
#define STACK_LOCAL_OFFSET      64
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

#define InLen           ((16*1)+8)
#define PBlockLen       (16*5)
#define CurCount        (16*4)
#define OrigIV          (16*3)
#define PBlockEncKey	(16*2)
#define AadLen          (16*1)
#define AadHash         (16*0)
#define very_big_loop_nblocks   128
#define big_loop_nblocks        48
#define NROUNDS		9

#define ymm7x xmm7
#define ymm6x xmm6
#define ymm12x xmm12
#define zmm14x xmm14
#define xmm11y ymm11
#define xmm2z zmm2
#define ymm11x xmm11
#define zmm11y ymm11
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

#define STACK_OFFSET    0
#define arg1 %rdi
#define arg2 %rsi
#define arg3 %rdx
#define arg4 %rcx
#define arg5 %r8
#define arg6 %r9
#define arg7 STACK_OFFSET+8*1(%r14)
#define arg8 STACK_OFFSET+8*2(%r14)
#define arg9 STACK_OFFSET+8*3(%r14)
#define arg10 STACK_OFFSET+8*4(%r14)
#define arg11 STACK_OFFSET+8*5(%r14)

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

#define key_expansion_1_192_avx(PARAM)                  \
        vpshufd $0xff, %xmm2, %xmm2;                    \
        vshufps $0x10, %xmm1, %xmm3, %xmm3;             \
        vpxor   %xmm3, %xmm1, %xmm1;                    \
        vshufps $0x8c, %xmm1, %xmm3, %xmm3;             \
        vpxor   %xmm3, %xmm1, %xmm1;                    \
        vpxor   %xmm2, %xmm1, %xmm1;                    \
        vmovdqu %xmm1, PARAM(EXP_ENC_KEYS);

#define key_expansion_2_192_avx(PARAM)                  \
        vmovdqa %xmm4, %xmm5;                   \
        vpslldq $4, %xmm5, %xmm5;               \
        vshufps $0xf0, %xmm1, %xmm6, %xmm6;     \
        vpxor %xmm5, %xmm6, %xmm6;              \
        vpxor %xmm6, %xmm4, %xmm4;              \
        vpshufd $0xe, %xmm4, %xmm7;             \
        vmovdqu %xmm7, PARAM(EXP_ENC_KEYS);

#define key_expansion_256_avx			\
	vpshufd $0xff, %xmm2, %xmm2;                    \
        vshufps $0x10, %xmm1, %xmm3, %xmm3;             \
        vpxor   %xmm3, %xmm1, %xmm1;                    \
        vshufps $0x8c, %xmm1, %xmm3, %xmm3;             \
        vpxor   %xmm3, %xmm1, %xmm1;                    \
        vpxor   %xmm2, %xmm1, %xmm1;

#define key_expansion_256_avx_2                   \
	vpshufd $0xaa, %xmm2, %xmm2;                    \
        vshufps $0x10, %xmm4, %xmm3, %xmm3;             \
        vpxor   %xmm3, %xmm4, %xmm4;                    \
        vshufps $0x8c, %xmm4, %xmm3, %xmm3;             \
        vpxor   %xmm3, %xmm4, %xmm4;                    \
        vpxor   %xmm2, %xmm4, %xmm4;

#define key_dec_192_avx(PARAM)                          \
        vmovdqa 16*PARAM(EXP_ENC_KEYS), %xmm0;          \
        vaesimc %xmm0, %xmm1;                           \
        vmovdqa %xmm1, 16*(12-PARAM)(EXP_DEC_KEYS);     \

#define ENCRYPT_SINGLE_BLOCK(GDATA, XMM0, NROUNDS)       \
        vpxorq (GDATA), XMM0, XMM0;             \
.if NROUNDS == 9;	\
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
.elseif NROUNDS == 11; \
	vaesenc 16*1(GDATA), XMM0, XMM0;        \
        vaesenc 16*2(GDATA), XMM0, XMM0;        \
        vaesenc 16*3(GDATA), XMM0, XMM0;        \
        vaesenc 16*4(GDATA), XMM0, XMM0;        \
        vaesenc 16*5(GDATA), XMM0, XMM0;        \
        vaesenc 16*6(GDATA), XMM0, XMM0;        \
        vaesenc 16*7(GDATA), XMM0, XMM0;        \
        vaesenc 16*8(GDATA), XMM0, XMM0;        \
        vaesenc 16*9(GDATA), XMM0, XMM0;        \
	vaesenc 16*10(GDATA), XMM0, XMM0;        \
        vaesenc 16*11(GDATA), XMM0, XMM0;        \
        vaesenclast 16*12(GDATA), XMM0, XMM0;   \
.elseif NROUNDS == 13; \
	vaesenc 16*1(GDATA), XMM0, XMM0;        \
        vaesenc 16*2(GDATA), XMM0, XMM0;        \
        vaesenc 16*3(GDATA), XMM0, XMM0;        \
        vaesenc 16*4(GDATA), XMM0, XMM0;        \
        vaesenc 16*5(GDATA), XMM0, XMM0;        \
        vaesenc 16*6(GDATA), XMM0, XMM0;        \
        vaesenc 16*7(GDATA), XMM0, XMM0;        \
        vaesenc 16*8(GDATA), XMM0, XMM0;        \
        vaesenc 16*9(GDATA), XMM0, XMM0;        \
        vaesenc 16*10(GDATA), XMM0, XMM0;        \
        vaesenc 16*11(GDATA), XMM0, XMM0;        \
	vaesenc 16*12(GDATA), XMM0, XMM0;        \
        vaesenc 16*13(GDATA), XMM0, XMM0;        \
        vaesenclast 16*14(GDATA), XMM0, XMM0;   \
.endif;	\

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

#define simd_store_avx_15(DST, SRC, SIZE, TMP, IDX)	\
	xor IDX, IDX;		\
	test	$8, SIZE;       \
	jz      4f;           	\
	vmovq	SRC, (DST, IDX, 1);	\
	vpsrldq	$8, SRC, SRC;	\
	add	$8, IDX;	\
4:;	\
	vmovq 	SRC, TMP;	\
	test	$4, SIZE;       \
        jz      3f;            \
	mov	DWORD(TMP), (DST, IDX, 1);	\
	shr	$32, TMP;	\
	add	$4, IDX;	\
3:;	\
	test	$2, SIZE;       \
        jz      2f;            \
        mov     WORD(TMP), (DST, IDX, 1);   \
        shr     $16, TMP;       \
        add     $2, IDX;        \
2:;	\
	test	$1, SIZE;          \
	jz	1f;	\
	mov	BYTE(TMP), (DST, IDX, 1);	\
1:;

#define VCLMUL_STEP1_6(KP, HI, TMP, TH, TM, TL) \
        vmovdqu64       HashKey_4(KP) , TMP;            \
        vpclmulqdq      $0x11, TMP, HI, TH;             \
        vpclmulqdq      $0x00, TMP, HI, TL;             \
        vpclmulqdq      $0x01, TMP, HI, TM;             \
        vpclmulqdq      $0x10, TMP, HI, TMP;            \
        vpxorq          TMP, TM, TM;

#define VCLMUL_STEP1_7(KP, HI, TMP, TH, TM, TL, HKEY) \
        vmovdqa64       HKEY , TMP;            \
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

#define VCLMUL_STEP2_9(KP, HI, LO, TMP0, TMP1, TMP2, TH, TM, TL)  \
        vmovdqu64       HashKey_8(KP), TMP0;                    \
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
        VHPXORI4x128(HI, TMP2)                                  \
        VHPXORI4x128(LO, TMP1)                                  \

#define VCLMUL_STEP2_11(KP, HI, LO, TMP0, TMP1, TMP2, TH, TM, TL, HKEY, HXOR)  \
        vmovdqa64       HKEY, TMP0;                             \
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
        .if HXOR == 4;                                      \
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
                VCLMUL_STEP1_6(KP, HI, TMP1, TH, TM, TL)         \
        .elseif NBLOCKS == 7;                                           \
                vmovdqu64       HashKey_3(KP), TMP2;                    \
                vmovdqa64      mask_out_top_block(%rip), TMP1;                            \
                vpandq          TMP1, TMP2, TMP2;                             \
                vpandq          TMP1, HI, HI;                               \
                VCLMUL_STEP1_7(NULL, HI, TMP1, TH, TM, TL, TMP2)       \
        .elseif NBLOCKS == 6;                                           \
                vmovdqu64       HashKey_2(KP), YWORD(TMP2);             \
                VCLMUL_STEP1_7(NULL, YWORD(HI), YWORD(TMP1), YWORD(TH), YWORD(TM), YWORD(TL), YWORD(TMP2))     \
        .elseif NBLOCKS == 5;                                   \
                vmovdqu64       HashKey_1(KP), XWORD(TMP2);     \
                VCLMUL_STEP1_7(NULL, XWORD(HI), XWORD(TMP1), XWORD(TH), XWORD(TM), XWORD(TL), XWORD(TMP2))     \
        .else;                                                   \
                vpxorq          TH, TH, TH;                     \
                vpxorq          TM, TM, TM;                     \
                vpxorq          TL, TL, TL;                     \
        .endif;

#define VCLMUL_1_TO_8_STEP2(KP, HI, LO, TMP0, TMP1, TMP2, TH, TM, TL, NBLOCKS)  \
        .if NBLOCKS == 8;                                                       \
                VCLMUL_STEP2_9(KP, HI, LO, TMP0, TMP1, TMP2, TH, TM, TL)           \
        .elseif NBLOCKS == 7;                                                   \
                vmovdqu64       HashKey_7(KP), TMP2;                            \
                VCLMUL_STEP2_11(NULL, HI, LO, TMP0, TMP1, TMP2, TH, TM, TL, TMP2, 4)   \
        .elseif NBLOCKS == 6;                                                   \
                vmovdqu64       HashKey_6(KP), TMP2;                            \
                VCLMUL_STEP2_11(NULL, HI, LO, TMP0, TMP1, TMP2, TH, TM, TL, TMP2, 4)   \
        .elseif NBLOCKS == 5;                                                   \
                vmovdqu64       HashKey_5(KP), TMP2;                            \
                VCLMUL_STEP2_11(NULL, HI, LO, TMP0, TMP1, TMP2, TH, TM, TL, TMP2, 4)   \
        .elseif NBLOCKS == 4;                                                   \
                vmovdqu64       HashKey_4(KP), TMP2;                            \
                VCLMUL_STEP2_11(NULL, HI, LO, TMP0, TMP1, TMP2, TH, TM, TL, TMP2, 4)   \
        .elseif NBLOCKS == 3;                                                   \
                vmovdqu64       HashKey_3(KP), TMP2;                            \
                vmovdqa64       mask_out_top_block(%rip), TMP1;                                   \
                vpandq          TMP1, TMP2, TMP2;                                       \
                vpandq          TMP1, LO, LO;                                   \
                VCLMUL_STEP2_11(NULL, HI, LO, TMP0, TMP1, TMP2, TH, TM, TL, TMP2, 4)   \
        .elseif NBLOCKS == 2;                                                   \
                vmovdqu64       HashKey_2(KP), YWORD(TMP2);                     \
                VCLMUL_STEP2_11(NULL, YWORD(HI), YWORD(LO), YWORD(TMP0), YWORD(TMP1), YWORD(TMP2), YWORD(TH), YWORD(TM), YWORD(TL), YWORD(TMP2), 2)            \
        .elseif NBLOCKS == 1;                           \
                vmovdqu64       HashKey_1(KP), XWORD(TMP2);                     \
                VCLMUL_STEP2_11(NULL, XWORD(HI), XWORD(LO), XWORD(TMP0), XWORD(TMP1), XWORD(TMP2), XWORD(TH), XWORD(TM), XWORD(TL), XWORD(TMP2), 1)            \
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
11:;                                      \
        cmp             $128, T2;                       \
        jl              12f;              \
        vmovdqu64       64*0(T1), ZT2;                  \
        vmovdqu64       64*1(T1), ZT1;                  \
        vpshufb         SHFMSK, ZT2, ZT2;               \
        vpshufb         SHFMSK, ZT1, ZT1;               \
        vpxorq          ZWORD(AAD_HASH), ZT2, ZT2;      \
        \
        VCLMUL_STEP1_6(GDATA_KEY, ZT1, ZT0, TH, TM, TL)   \
        VCLMUL_STEP2_9(GDATA_KEY, ZT1, ZT2, ZT0, ZT3, ZT4, TH, TM, TL)    \
        VCLMUL_REDUCE(AAD_HASH, XWORD(POLY), XWORD(ZT1), XWORD(ZT2), XWORD(ZT0), XWORD(ZT3))    \
        \
        sub             $128, T2;                       \
        je              10f;                 \
        add             $128, T1;                       \
        jmp             11b;               \
        \
12:;                             \
        or              T2, T2;                 \
        jz              10f;         \
        lea             byte64_len_to_mask_table(%rip), T3;             \
        lea             (T3, T2, 8), T3;        \
        add             $15, T2;                \
        and             $-16, T2;               \
        shr             $4, T2;                 \
        cmp             $7, T2;                 \
        je              7f;          \
        cmp             $6, T2;         \
        je              6f;          \
        cmp             $5, T2;         \
        je              5f;          \
        cmp             $4, T2;         \
        je              4f;          \
        cmp             $3, T2;         \
        je              3f;          \
        cmp             $2, T2;         \
        je              2f;          \
        cmp             $1, T2;         \
        je              1f;          \
        \
8:;                                         \
        sub             $512, T3;                       \
        kmovq           (T3), MASKREG;                  \
        vmovdqu8        (T1), ZT2;                      \
        vmovdqu8        64(T1), ZT1{MASKREG}{z};        \
        vpshufb         SHFMSK, ZT2, ZT2;               \
        vpshufb         SHFMSK, ZT1, ZT1;               \
        vpxorq          ZWORD(AAD_HASH), ZT2, ZT2;      \
        VCLMUL_1_TO_8_STEP1(GDATA_KEY, ZT1, ZT0, ZT3, TH, TM, TL, 8)    \
        VCLMUL_1_TO_8_STEP2(GDATA_KEY, ZT1, ZT2, ZT0, ZT3, ZT4, TH, TM, TL, 8)  \
        jmp             9f;               \
7:;                                         \
        sub             $512, T3;                       \
        kmovq           (T3), MASKREG;                  \
        vmovdqu8        (T1), ZT2;                      \
        vmovdqu8        64(T1), ZT1{MASKREG}{z};        \
        vpshufb         SHFMSK, ZT2, ZT2;               \
        vpshufb         SHFMSK, ZT1, ZT1;               \
        vpxorq          ZWORD(AAD_HASH), ZT2, ZT2;      \
        VCLMUL_1_TO_8_STEP1(GDATA_KEY, ZT1, ZT0, ZT3, TH, TM, TL, 7)    \
        VCLMUL_1_TO_8_STEP2(GDATA_KEY, ZT1, ZT2, ZT0, ZT3, ZT4, TH, TM, TL, 7)  \
        jmp             9f;               \
6:;                                         \
        sub             $512, T3;                       \
        kmovq           (T3), MASKREG;                  \
        vmovdqu8        (T1), ZT2;                      \
        vmovdqu8        64(T1), YWORD(ZT1){MASKREG}{z};        \
        vpshufb         SHFMSK, ZT2, ZT2;               \
        vpshufb         YWORD(SHFMSK), YWORD(ZT1), YWORD(ZT1);               \
        vpxorq          ZWORD(AAD_HASH), ZT2, ZT2;      \
        VCLMUL_1_TO_8_STEP1(GDATA_KEY, ZT1, ZT0, ZT3, TH, TM, TL, 6)    \
        VCLMUL_1_TO_8_STEP2(GDATA_KEY, ZT1, ZT2, ZT0, ZT3, ZT4, TH, TM, TL, 6)  \
        jmp             9f;               \
5:;                                         \
        sub             $512, T3;                       \
        kmovq           (T3), MASKREG;                  \
        vmovdqu8        (T1), ZT2;                      \
        vmovdqu8        64(T1), XWORD(ZT1){MASKREG}{z};        \
        vpshufb         SHFMSK, ZT2, ZT2;               \
        vpshufb         XWORD(SHFMSK), XWORD(ZT1), XWORD(ZT1);               \
        vpxorq          ZWORD(AAD_HASH), ZT2, ZT2;      \
        VCLMUL_1_TO_8_STEP1(GDATA_KEY, ZT1, ZT0, ZT3, TH, TM, TL, 5)    \
        VCLMUL_1_TO_8_STEP2(GDATA_KEY, ZT1, ZT2, ZT0, ZT3, ZT4, TH, TM, TL, 5)  \
        jmp             9f;               \
4:;                                         \
        kmovq           (T3), MASKREG;                  \
        vmovdqu8        (T1), ZT2{MASKREG}{z};          \
        vpshufb         SHFMSK, ZT2, ZT2;               \
        vpxorq          ZWORD(AAD_HASH), ZT2, ZT2;      \
        VCLMUL_1_TO_8_STEP1(GDATA_KEY, ZT1, ZT0, ZT3, TH, TM, TL, 4)    \
        VCLMUL_1_TO_8_STEP2(GDATA_KEY, ZT1, ZT2, ZT0, ZT3, ZT4, TH, TM, TL, 4)  \
        jmp             9f;               \
3:;                                         \
        kmovq           (T3), MASKREG;                  \
        vmovdqu8        (T1), ZT2{MASKREG}{z};          \
        vpshufb         SHFMSK, ZT2, ZT2;               \
        vpxorq          ZWORD(AAD_HASH), ZT2, ZT2;      \
        VCLMUL_1_TO_8_STEP1(GDATA_KEY, ZT1, ZT0, ZT3, TH, TM, TL, 3)    \
        VCLMUL_1_TO_8_STEP2(GDATA_KEY, ZT1, ZT2, ZT0, ZT3, ZT4, TH, TM, TL, 3)  \
        jmp             9f;               \
2:;                                         \
        kmovq           (T3), MASKREG;                  \
        vmovdqu8        (T1), YWORD(ZT2){MASKREG}{z};          \
        vpshufb         YWORD(SHFMSK), YWORD(ZT2), YWORD(ZT2);               \
        vpxorq          ZWORD(AAD_HASH), ZT2, ZT2;      \
        VCLMUL_1_TO_8_STEP1(GDATA_KEY, ZT1, ZT0, ZT3, TH, TM, TL, 2)    \
	VCLMUL_1_TO_8_STEP2(GDATA_KEY, ZT1, ZT2, ZT0, ZT3, ZT4, TH, TM, TL, 2)  \
        jmp             9f;               \
1:;                                         \
        kmovq           (T3), MASKREG;                  \
        vmovdqu8        (T1), XWORD(ZT2){MASKREG}{z};          \
        vpshufb         XWORD(SHFMSK), XWORD(ZT2), XWORD(ZT2);               \
        vpxorq          ZWORD(AAD_HASH), ZT2, ZT2;      \
        VCLMUL_1_TO_8_STEP1(GDATA_KEY, ZT1, ZT0, ZT3, TH, TM, TL, 1)    \
        VCLMUL_1_TO_8_STEP2(GDATA_KEY, ZT1, ZT2, ZT0, ZT3, ZT4, TH, TM, TL, 1)  \
9:;                                      \
        VCLMUL_REDUCE(AAD_HASH, XWORD(POLY), XWORD(ZT1), XWORD(ZT2), XWORD(ZT0), XWORD(ZT3))    \
10:;

#define CALC_J0(KEY, IV, IV_LEN, J0, ZT0, ZT1, ZT2, ZT3, ZT4, ZT5, ZT6, ZT7, ZT8, ZT9, T1, T2, T3, MASKREG)       \
        CALC_AAD_HASH(IV, IV_LEN, J0, KEY, ZT0, ZT1, ZT2, ZT3, ZT4, ZT5, ZT6, ZT7, ZT8, ZT9, T1, T2, T3, MASKREG)       \
	mov             IV_LEN, T1;             \
        shl             $3, T1;                 \
        vmovq           T1, XWORD(ZT2);         \
	vpxorq          ZWORD(J0), ZT2, ZT2;         \
	VCLMUL_1_TO_8_STEP1(KEY, ZT1, ZT0, ZT3, ZT7, ZT6, ZT5, 1)  \
        VCLMUL_1_TO_8_STEP2(KEY, ZT1, ZT2, ZT0, ZT3, ZT4, ZT7, ZT6, ZT5, 1)        \
        VCLMUL_REDUCE(J0, XWORD(ZT8), XWORD(ZT1), XWORD(ZT2), XWORD(ZT0), XWORD(ZT3))  \
        vpshufb         SHUF_MASK(%rip), J0, J0;

#define GCM_INIT(GDATA_KEY, GDATA_CTX, IV, A_IN, A_LEN, GPR1, GPR2, GPR3, MASKREG, AAD_HASH, CUR_COUNT, ZT0, ZT1, ZT2, ZT3, ZT4, ZT5, ZT6, ZT7, ZT8, ZT9, IV_LEN, NUM_PARAMS)    \
	CALC_AAD_HASH(A_IN, A_LEN, AAD_HASH, GDATA_KEY, ZT0, ZT1, ZT2, ZT3, ZT4, ZT5, ZT6, ZT7, ZT8, ZT9, GPR1, GPR2, GPR3, MASKREG)    \
        mov             A_LEN, GPR1;                    \
        vmovdqu64       AAD_HASH, (GDATA_CTX);          \
        mov             GPR1, AadLen(GDATA_CTX);        \
        xor             GPR1, GPR1;                     \
        mov             GPR1, InLen(GDATA_CTX);         \
        mov             GPR1, PBlockLen(GDATA_CTX);     \
        .if NUM_PARAMS == 22;   \
        CALC_J0(GDATA_KEY, IV, IV_LEN, CUR_COUNT, ZT0, ZT1, ZT2, ZT3, ZT4, ZT5, ZT6, ZT7, ZT8, ZT9, GPR1, GPR2, GPR3, MASKREG)  \
        .else;  \
        vmovdqu8        ONEf(%rip), CUR_COUNT;          \
        mov             IV, GPR2;                       \
        mov             $0xfff, GPR1;                   \
        kmovq           GPR1, MASKREG;                  \
        vmovdqu8        (GPR2), CUR_COUNT{MASKREG};     \
        .endif; \
        vmovdqu64       CUR_COUNT, OrigIV(GDATA_CTX);   \
        vpshufb         SHUF_MASK(%rip), CUR_COUNT, CUR_COUNT;     \
        vmovdqu         CUR_COUNT, CurCount(GDATA_CTX);

#define GCM_COMPLETE(GDATA_KEY, GDATA_CTX, AUTH_TAG, AUTH_TAG_LEN, END_DEC, INSTANCE_TYPE, NROUNDS) \
        vmovdqu HashKey(GDATA_KEY), %xmm13; \
        vmovdqu OrigIV(GDATA_CTX), %xmm9; \
        ENCRYPT_SINGLE_BLOCK(GDATA_KEY, %xmm9, NROUNDS) \
        .ifc INSTANCE_TYPE, multi_call; \
        vmovdqu (GDATA_CTX), %xmm14; \
        mov PBlockLen(GDATA_CTX), %r12; \
        cmp $0, %r12; \
        je 36f; \
        GHASH_MUL(%xmm14, %xmm13, %xmm0, %xmm10, %xmm11, %xmm5, %xmm6) \
        vmovdqu %xmm14, (GDATA_CTX); \
36:; \
        .endif; \
        mov AadLen(GDATA_CTX), %r12; \
        mov InLen(GDATA_CTX), %rax; \
        shl $3, %r12; \
        vmovd %r12d, %xmm15; \
        shl $3, %rax; \
        vmovq %rax, %xmm1; \
        vpslldq $8, %xmm15, %xmm15; \
        vpxor %xmm1, %xmm15, %xmm15; \
        vpxor %xmm15, %xmm14, %xmm14; \
        GHASH_MUL(%xmm14, %xmm13, %xmm0, %xmm10, %xmm11, %xmm5, %xmm6) \
        vpshufb SHUF_MASK(%rip), %xmm14, %xmm14; \
        vpxor %xmm14, %xmm9, %xmm9; \
31:; \
        mov AUTH_TAG, %r10; \
        mov AUTH_TAG_LEN, %r11; \
        cmp $16, %r11; \
        je 34f; \
        cmp $12, %r11; \
        je 33f; \
        cmp $8, %r11; \
        je 32f; \
        simd_store_avx_15(%r10, %xmm9, %r11, %r12, %rax) \
        jmp 35f; \
32:; \
        vmovq %xmm9, %rax; \
        mov %rax, (%r10); \
        jmp 35f; \
33:; \
        vmovq %xmm9, %rax; \
        mov %rax, (%r10); \
        vpsrldq $8, %xmm9, %xmm9; \
        vmovd %xmm9, %eax; \
        mov %eax, 8(%r10); \
        jmp 35f; \
34:; \
        vmovdqu %xmm9, (%r10); \
35:;	\

#define READ_SMALL_DATA_INPUT(OUTPUT, INPUT, LENGTH ,TMP1, MASK)        \
        cmp             $16, LENGTH;                            \
        jge             1f;                  \
        lea             byte_len_to_mask_table(%rip), TMP1;                           \
        kmovw           (TMP1, LENGTH, 2), MASK;                \
        vmovdqu8        (INPUT), OUTPUT{MASK}{z};               \
        jmp             2f;                   \
1:;                                         \
        vmovdqu8        (INPUT), OUTPUT;                        \
        mov             $0xffff, TMP1;                          \
        kmovq           TMP1, MASK;                             \
2:;

#define PARTIAL_BLOCK(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, PLAIN_CYPH_LEN, DATA_OFFSET, AAD_HASH, ENC_DEC, GPTMP0, GPTMP1, GPTMP2, ZTMP0, ZTMP1, ZTMP2, ZTMP3, ZTMP4, ZTMP5, ZTMP6, ZTMP7, ZTMP8, ZTMP9, MASKREG)               \
        mov             PBlockLen(GDATA_CTX), GPTMP0;   \
        or              GPTMP0, GPTMP0;                 \
        je              4f;            \
        READ_SMALL_DATA_INPUT(XWORD(ZTMP0), PLAIN_CYPH_IN, PLAIN_CYPH_LEN, GPTMP1, MASKREG)        \
        vmovdqu64       PBlockEncKey(GDATA_CTX), XWORD(ZTMP1);  \
        vmovdqu64       HashKey(GDATA_KEY), XWORD(ZTMP2);       \
        lea             SHIFT_MASK(%rip), GPTMP1;               \
        add             GPTMP0, GPTMP1;                         \
        vmovdqu64       (GPTMP1), XWORD(ZTMP3);                 \
        vpshufb         XWORD(ZTMP3), XWORD(ZTMP1), XWORD(ZTMP1);       \
        .ifc ENC_DEC, DEC;                                      \
        vmovdqa64       XWORD(ZTMP0), XWORD(ZTMP4);             \
        .endif;                                                 \
        vpxorq          XWORD(ZTMP0), XWORD(ZTMP1), XWORD(ZTMP1);               \
        mov             PLAIN_CYPH_LEN, GPTMP2;                 \
        add             GPTMP0, GPTMP2;                         \
        sub             $16, GPTMP2;                            \
        jge             1f;                         \
        sub             GPTMP2, GPTMP1;                         \
1:;                                                \
        vmovdqu64       (ALL_F - SHIFT_MASK)(GPTMP1), XWORD(ZTMP0);       \
        vpand           XWORD(ZTMP0), XWORD(ZTMP1),  XWORD(ZTMP1);              \
        .ifc ENC_DEC, DEC;                                      \
        vpand           XWORD(ZTMP0), XWORD(ZTMP4), XWORD(ZTMP4);               \
        vpshufb         SHUF_MASK(%rip), XWORD(ZTMP4), XWORD(ZTMP4);            \
        vpshufb         XWORD(ZTMP3), XWORD(ZTMP4), XWORD(ZTMP4);               \
        vpxorq          XWORD(ZTMP4), AAD_HASH, AAD_HASH;       \
        .else;          \
        vpshufb         SHUF_MASK(%rip), XWORD(ZTMP1), XWORD(ZTMP1);    \
        vpshufb         XWORD(ZTMP3), XWORD(ZTMP1), XWORD(ZTMP1);       \
        vpxorq          XWORD(ZTMP1), AAD_HASH, AAD_HASH;               \
        .endif; \
        cmp             $0, GPTMP2;                     \
        jl              2f;            \
        \
        GHASH_MUL(AAD_HASH, XWORD(ZTMP2), XWORD(ZTMP5), XWORD(ZTMP6), XWORD(ZTMP7), XWORD(ZTMP8), XWORD(ZTMP9)) \
	movq		$0, PBlockLen(GDATA_CTX);	\
        mov             GPTMP0, GPTMP1; \
        mov             $16, GPTMP0;    \
        sub             GPTMP1, GPTMP0; \
        jmp             3f;  \
2:;   \
        add             PLAIN_CYPH_LEN, PBlockLen(GDATA_CTX);   \
        mov             PLAIN_CYPH_LEN, GPTMP0;                 \
3:;         \
        lea             byte_len_to_mask_table(%rip), GPTMP1;                         \
        kmovw           (GPTMP1, GPTMP0, 2), MASKREG;           \
        vmovdqu64       AAD_HASH, (GDATA_CTX);          \
        .ifc ENC_DEC, ENC;      \
        vpshufb         SHUF_MASK(%rip), XWORD(ZTMP1), XWORD(ZTMP1);            \
        vpshufb         XWORD(ZTMP3), XWORD(ZTMP1), XWORD(ZTMP1);       \
        .endif;                 \
        vmovdqu8        XWORD(ZTMP1), (CYPH_PLAIN_OUT, DATA_OFFSET, 1){MASKREG};        \
        add             GPTMP0, DATA_OFFSET;    \
4:;

#define INITIAL_BLOCKS_16(IN, OUT, KP, DATA_OFFSET, GHASH, CTR, CTR_CHECK, ADDBE_4x4, ADDBE_1234, T0, T1, T2, T3, T4, T5, T6, T7, T8, SHUF_MASK, ENC_DEC, BLK_OFFSET, DATA_DISPL, NROUNDS) \
        cmp             $(256 - 16), BYTE(CTR_CHECK); \
        jae             1f; \
        vpaddd          ADDBE_1234 ,CTR, T5; \
        vpaddd          ADDBE_4x4, T5, T6; \
        vpaddd          ADDBE_4x4, T6, T7; \
        vpaddd          ADDBE_4x4, T7, T8; \
        jmp             2f; \
1:; \
        vpshufb         SHUF_MASK, CTR, CTR; \
        vmovdqa64       ddq_add_4444(%rip), T8; \
        vpaddd          ddq_add_1234(%rip), CTR, T5; \
        vpaddd          T8, T5, T6; \
        vpaddd          T8, T6, T7; \
        vpaddd          T8, T7, T8; \
        vpshufb         SHUF_MASK, T5, T5; \
        vpshufb         SHUF_MASK, T6, T6; \
        vpshufb         SHUF_MASK, T7, T7; \
        vpshufb         SHUF_MASK, T8, T8; \
2:; \
        vshufi64x2      $0xff, T8, T8, CTR; \
        add             $16, BYTE(CTR_CHECK); \
        vmovdqu8        DATA_DISPL(IN, DATA_OFFSET), T0; \
        vmovdqu8        64 + DATA_DISPL(DATA_OFFSET, IN), T1; \
        vmovdqu8        128 + DATA_DISPL(DATA_OFFSET, IN), T2; \
        vmovdqu8        192 + DATA_DISPL(DATA_OFFSET, IN), T3; \
        vbroadcastf64x2 (KP), T4; \
        vpxorq          T4, T5, T5; \
        vpxorq          T4, T6, T6; \
        vpxorq          T4, T7, T7; \
        vpxorq          T4, T8, T8; \
.if NROUNDS==9;	\
        vbroadcastf64x2 16*1(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
	vbroadcastf64x2 16*2(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
	vbroadcastf64x2 16*3(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
	vbroadcastf64x2 16*4(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
	vbroadcastf64x2 16*5(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
	vbroadcastf64x2 16*6(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
	vbroadcastf64x2 16*7(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
	vbroadcastf64x2 16*8(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
	vbroadcastf64x2 16*9(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
        vbroadcastf64x2 16*10(KP), T4; \
.elseif NROUNDS == 11; \
        vbroadcastf64x2 16*1(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
        vbroadcastf64x2 16*2(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
        vbroadcastf64x2 16*3(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
        vbroadcastf64x2 16*4(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
        vbroadcastf64x2 16*5(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
        vbroadcastf64x2 16*6(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
        vbroadcastf64x2 16*7(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
        vbroadcastf64x2 16*8(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
        vbroadcastf64x2 16*9(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
	vbroadcastf64x2 16*10(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
        vbroadcastf64x2 16*11(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
        vbroadcastf64x2 16*12(KP), T4; \
.elseif NROUNDS == 13; \
        vbroadcastf64x2 16*1(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
        vbroadcastf64x2 16*2(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
        vbroadcastf64x2 16*3(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
        vbroadcastf64x2 16*4(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
        vbroadcastf64x2 16*5(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
        vbroadcastf64x2 16*6(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
        vbroadcastf64x2 16*7(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
        vbroadcastf64x2 16*8(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
        vbroadcastf64x2 16*9(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
	vbroadcastf64x2 16*10(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
        vbroadcastf64x2 16*11(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
        vbroadcastf64x2 16*12(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
        vbroadcastf64x2 16*13(KP), T4; \
        vaesenc         T4, T5, T5; \
        vaesenc         T4, T6, T6; \
        vaesenc         T4, T7, T7; \
        vaesenc         T4, T8, T8; \
        vbroadcastf64x2 16*14(KP), T4; \
.endif;	\
        vaesenclast     T4, T5, T5; \
        vaesenclast     T4, T6, T6; \
        vaesenclast     T4, T7, T7; \
        vaesenclast     T4, T8, T8; \
        vpxorq          T0, T5, T5; \
        vpxorq          T1, T6, T6; \
        vpxorq          T2, T7, T7; \
        vpxorq          T3, T8, T8; \
        vmovdqu8        T5, DATA_DISPL(OUT, DATA_OFFSET); \
        vmovdqu8        T6, 64 + DATA_DISPL(DATA_OFFSET, OUT); \
        vmovdqu8        T7, 128 + DATA_DISPL(DATA_OFFSET, OUT); \
        vmovdqu8        T8, 192 + DATA_DISPL(DATA_OFFSET, OUT); \
.ifc  ENC_DEC, DEC; \
        vpshufb         SHUF_MASK, T0, T5; \
        vpshufb         SHUF_MASK, T1, T6; \
        vpshufb         SHUF_MASK, T2, T7; \
        vpshufb         SHUF_MASK, T3, T8; \
.else; \
        vpshufb         SHUF_MASK, T5, T5; \
        vpshufb         SHUF_MASK, T6, T6; \
        vpshufb         SHUF_MASK, T7, T7; \
        vpshufb         SHUF_MASK, T8, T8; \
.endif; \
.ifnc GHASH, no_ghash; \
        vpxorq          GHASH, T5, T5; \
.endif; \
        vmovdqa64       T5, BLK_OFFSET(%rsp); \
        vmovdqa64       T6, 64 + BLK_OFFSET(%rsp); \
        vmovdqa64       T7, 128 + BLK_OFFSET(%rsp); \
        vmovdqa64       T8, 192 + BLK_OFFSET(%rsp);

#define GHASH_16_ENCRYPT_16_PARALLEL(GDATA, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, DATA_OFFSET, CTR_BE, CTR_CHECK, HASHKEY_OFFSET, AESOUT_BLK_OFFSET, GHASHIN_BLK_OFFSET, SHFMSK, ZT1, ZT2, ZT3, ZT4, ZT5, ZT6, ZT7, ZT8, ZT9, ZT10, ZT11, ZT12, ZT13, ZT14, ZT15, ZT16, ZT17, ZT18, ZT19, ZT20, ZT21, ZT22, ZT23, ADDBE_4x4, ADDBE_1234, TO_REDUCE_L, TO_REDUCE_H, TO_REDUCE_M, DO_REDUCTION, ENC_DEC, DATA_DISPL, GHASH_IN, NROUNDS)   \
        cmp             $240, BYTE(CTR_CHECK);          \
        jae             1f;          \
	vpaddd          ADDBE_1234, CTR_BE, ZT1;        \
        vpaddd          ADDBE_4x4, ZT1, ZT2;    \
        vpaddd           ADDBE_4x4, ZT2, ZT3;    \
        vpaddd           ADDBE_4x4, ZT3, ZT4;    \
	jmp             2f;                     \
1:;	\
        vpshufb         SHFMSK, CTR_BE, CTR_BE;         \
        vmovdqa64       ddq_add_4444(%rip), ZT4;        \
        vpaddd          ddq_add_1234(%rip), CTR_BE, ZT1;        \
        vpaddd          ZT4, ZT1, ZT2;  \
        vpaddd          ZT4, ZT2, ZT3;  \
        vpaddd          ZT4, ZT3, ZT4;  \
        vpshufb         SHFMSK, ZT1, ZT1;       \
        vpshufb         SHFMSK, ZT2, ZT2;       \
        vpshufb         SHFMSK, ZT3, ZT3;       \
        vpshufb         SHFMSK, ZT4, ZT4;       \
2:;     \
        vbroadcastf64x2 (GDATA), ZT17;  \
.ifnc GHASH_IN,no_ghash_in;	\
	vpxorq		GHASHIN_BLK_OFFSET(%rsp), GHASH_IN, ZT21;	\
.else;	\
        vmovdqa64       GHASHIN_BLK_OFFSET(%rsp), ZT21; \
.endif;	\
        vmovdqu64       HASHKEY_OFFSET(GDATA), ZT19;            \
        vshufi64x2      $0xff, ZT4, ZT4, CTR_BE;                \
        add             $16, BYTE(CTR_CHECK);                   \
        vbroadcastf64x2 16(GDATA), ZT18;                        \
        vmovdqu64       HASHKEY_OFFSET + 64(GDATA), ZT20;       \
        vmovdqa64       GHASHIN_BLK_OFFSET + 64(%rsp), ZT22;    \
        vpxorq          ZT17, ZT1, ZT1; \
        vpxorq          ZT17, ZT2, ZT2; \
        vpxorq          ZT17, ZT3, ZT3; \
        vpxorq          ZT17, ZT4, ZT4;      \
        vbroadcastf64x2 32(GDATA), ZT17;        \
        vpclmulqdq      $0x11, ZT19, ZT21, ZT5; \
        vpclmulqdq      $0x00, ZT19, ZT21, ZT6; \
        vpclmulqdq      $0x01, ZT19, ZT21, ZT7; \
        vpclmulqdq      $0x10, ZT19, ZT21, ZT8; \
        vmovdqu64       HASHKEY_OFFSET + 128(GDATA), ZT19;      \
        vmovdqa64       GHASHIN_BLK_OFFSET + 128(%rsp), ZT21;   \
        vaesenc         ZT18, ZT1, ZT1;         \
        vaesenc         ZT18, ZT2, ZT2;         \
        vaesenc         ZT18, ZT3, ZT3;         \
        vaesenc         ZT18, ZT4, ZT4;         \
        vbroadcastf64x2 48(GDATA), ZT18;        \
        vpclmulqdq      $0x10, ZT20, ZT22, ZT11; \
        vpclmulqdq      $0x01, ZT20, ZT22, ZT12; \
        vpclmulqdq      $0x11, ZT20, ZT22, ZT9; \
        vpclmulqdq      $0x00, ZT20, ZT22, ZT10; \
        vmovdqu64       HASHKEY_OFFSET + 192(GDATA), ZT20;   \
        vmovdqa64       GHASHIN_BLK_OFFSET + 192(%rsp), ZT22;        \
        vaesenc         ZT17, ZT1, ZT1;         \
        vaesenc         ZT17, ZT2, ZT2;         \
        vaesenc         ZT17, ZT3, ZT3;         \
        vaesenc         ZT17, ZT4, ZT4;         \
        vbroadcastf64x2 64(GDATA), ZT17;        \
        vpclmulqdq      $0x10, ZT19, ZT21, ZT15; \
        vpclmulqdq      $0x01, ZT19, ZT21, ZT16; \
        vpclmulqdq      $0x11, ZT19, ZT21, ZT13; \
        vpclmulqdq      $0x00, ZT19, ZT21, ZT14; \
        vaesenc         ZT18, ZT1, ZT1;         \
        vaesenc         ZT18, ZT2, ZT2;         \
        vaesenc         ZT18, ZT3, ZT3;         \
        vaesenc         ZT18, ZT4, ZT4;         \
        vbroadcastf64x2 80(GDATA), ZT18;        \
        vpternlogq      $0x96, ZT13, ZT9, ZT5;  \
        vpternlogq      $0x96, ZT14, ZT10, ZT6; \
        vpternlogq      $0x96, ZT16, ZT12, ZT8; \
        vpternlogq      $0x96, ZT15, ZT11, ZT7; \
        vaesenc         ZT17, ZT1, ZT1;         \
        vaesenc         ZT17, ZT2, ZT2;         \
        vaesenc         ZT17, ZT3, ZT3;         \
        vaesenc         ZT17, ZT4, ZT4;         \
        vbroadcastf64x2 96(GDATA), ZT17;        \
        vmovdqu8        DATA_DISPL(DATA_OFFSET, PLAIN_CYPH_IN), ZT13; \
        vmovdqu8        64 + DATA_DISPL(DATA_OFFSET, PLAIN_CYPH_IN), ZT14; \
        vmovdqu8        128 + DATA_DISPL(DATA_OFFSET, PLAIN_CYPH_IN), ZT15; \
        vmovdqu8        192 + DATA_DISPL(DATA_OFFSET, PLAIN_CYPH_IN), ZT16; \
        vaesenc         ZT18, ZT1, ZT1;         \
        vaesenc         ZT18, ZT2, ZT2;         \
        vaesenc         ZT18, ZT3, ZT3;         \
        vaesenc         ZT18, ZT4, ZT4;         \
        vbroadcastf64x2 112(GDATA), ZT18;       \
        vpclmulqdq      $0x10, ZT20, ZT22, ZT11;        \
        vpclmulqdq      $0x01, ZT20, ZT22, ZT12;        \
        vpclmulqdq      $0x11, ZT20, ZT22, ZT9;         \
        vpclmulqdq      $0x00, ZT20, ZT22, ZT10;        \
        vaesenc         ZT17, ZT1, ZT1;         \
        vaesenc         ZT17, ZT2, ZT2;         \
        vaesenc         ZT17, ZT3, ZT3;         \
        vaesenc         ZT17, ZT4, ZT4;         \
        vbroadcastf64x2 128(GDATA), ZT17;       \
        .ifc DO_REDUCTION, first_time;  \
        vpternlogq      $0x96, ZT12, ZT8, ZT7;  \
        vpxorq          ZT11, ZT7, TO_REDUCE_M; \
        vpxorq          ZT9, ZT5, TO_REDUCE_H;  \
        vpxorq          ZT10, ZT6, TO_REDUCE_L; \
        .endif; \
        .ifc DO_REDUCTION, no_reduction;        \
        vpternlogq      $0x96, ZT12, ZT8, ZT7;  \
        vpternlogq      $0x96, ZT11, ZT7, TO_REDUCE_M;  \
        vpternlogq      $0x96, ZT9, ZT5, TO_REDUCE_H;   \
        vpternlogq      $0x96, ZT10, ZT6, TO_REDUCE_L;  \
        .endif; \
        .ifc DO_REDUCTION, final_reduction;     \
        vpternlogq      $0x96, ZT12, ZT8, ZT7;  \
        vpternlogq      $0x96, ZT11, TO_REDUCE_M, ZT7;  \
        vpsrldq         $8, ZT7, ZT11;  \
        vpslldq         $8, ZT7, ZT7;   \
        vmovdqa64       POLY2(%rip), XWORD(ZT12);       \
        .endif; \
        vaesenc         ZT18, ZT1, ZT1;         \
        vaesenc         ZT18, ZT2, ZT2;         \
        vaesenc         ZT18, ZT3, ZT3;         \
        vaesenc         ZT18, ZT4, ZT4;         \
        vbroadcastf64x2 144(GDATA), ZT18;        \
        .ifc DO_REDUCTION, final_reduction;     \
        vpternlogq      $0x96, ZT11, ZT9, ZT5;  \
        vpxorq          TO_REDUCE_H, ZT5, ZT5;  \
        vpternlogq      $0x96, ZT7, ZT10, ZT6;  \
        vpxorq          TO_REDUCE_L, ZT6, ZT6; \
        .endif; \
        vaesenc         ZT17, ZT1, ZT1; \
        vaesenc         ZT17, ZT2, ZT2; \
        vaesenc         ZT17, ZT3, ZT3; \
        vaesenc         ZT17, ZT4, ZT4; \
        vbroadcastf64x2 160(GDATA), ZT17;       \
        .ifc DO_REDUCTION, final_reduction;     \
        VHPXORI4x128(ZT5, ZT9) \
        VHPXORI4x128(ZT6, ZT10)        \
        .endif; \
        vaesenc         ZT18, ZT1, ZT1;         \
        vaesenc         ZT18, ZT2, ZT2;         \
        vaesenc         ZT18, ZT3, ZT3;         \
        vaesenc         ZT18, ZT4, ZT4;         \
        .if NROUNDS >= 11;      \
        vbroadcastf64x2 176(GDATA), ZT18;        \
        .endif; \
        .ifc DO_REDUCTION, final_reduction;     \
        vpclmulqdq      $0x01, XWORD(ZT6), XWORD(ZT12), XWORD(ZT10);    \
        vpslldq         $8, XWORD(ZT10), XWORD(ZT10);   \
        vpxorq          XWORD(ZT10), XWORD(ZT6), XWORD(ZT10);   \
        .endif; \
        .if NROUNDS >= 11;    \
        vaesenc         ZT17, ZT1, ZT1; \
        vaesenc         ZT17, ZT2, ZT2; \
        vaesenc         ZT17, ZT3, ZT3; \
        vaesenc         ZT17, ZT4, ZT4; \
        vbroadcastf64x2 192(GDATA), ZT17;       \
        vaesenc         ZT18, ZT1, ZT1;         \
        vaesenc         ZT18, ZT2, ZT2;         \
        vaesenc         ZT18, ZT3, ZT3;         \
        vaesenc         ZT18, ZT4, ZT4;         \
        .if NROUNDS == 13;    \
        vbroadcastf64x2 208(GDATA), ZT18;       \
        vaesenc         ZT17, ZT1, ZT1; \
        vaesenc         ZT17, ZT2, ZT2; \
        vaesenc         ZT17, ZT3, ZT3; \
        vaesenc         ZT17, ZT4, ZT4; \
        vbroadcastf64x2 224(GDATA), ZT17;       \
        vaesenc         ZT18, ZT1, ZT1;         \
        vaesenc         ZT18, ZT2, ZT2;         \
        vaesenc         ZT18, ZT3, ZT3;         \
        vaesenc         ZT18, ZT4, ZT4;         \
        .endif; \
        .endif; \
        .ifc DO_REDUCTION, final_reduction;     \
        vpclmulqdq      $0, XWORD(ZT10), XWORD(ZT12), XWORD(ZT9);       \
        vpsrldq         $4, XWORD(ZT9), XWORD(ZT9);     \
        vpclmulqdq      $0x10, XWORD(ZT10), XWORD(ZT12), XWORD(ZT11);      \
        vpslldq         $4, XWORD(ZT11), XWORD(ZT11);     \
        vpternlogq      $0x96, XWORD(ZT9), XWORD(ZT11), XWORD(ZT5);     \
        .endif; \
        vaesenclast         ZT17, ZT1, ZT1; \
        vaesenclast         ZT17, ZT2, ZT2; \
        vaesenclast         ZT17, ZT3, ZT3; \
        vaesenclast         ZT17, ZT4, ZT4; \
        vpxorq              ZT13, ZT1, ZT1; \
        vpxorq           ZT14, ZT2, ZT2; \
        vpxorq         ZT15, ZT3, ZT3; \
        vpxorq         ZT16, ZT4, ZT4; \
        vmovdqu8        ZT1, DATA_DISPL(DATA_OFFSET, CYPH_PLAIN_OUT);   \
        vmovdqu8        ZT2, 64 + DATA_DISPL(DATA_OFFSET, CYPH_PLAIN_OUT); \
        vmovdqu8        ZT3, 128 + DATA_DISPL(DATA_OFFSET, CYPH_PLAIN_OUT); \
        vmovdqu8        ZT4, 192 + DATA_DISPL(DATA_OFFSET, CYPH_PLAIN_OUT); \
        .ifc ENC_DEC, ENC;      \
        vpshufb         SHFMSK, ZT1, ZT1;       \
        vpshufb         SHFMSK, ZT2, ZT2;       \
        vpshufb         SHFMSK, ZT3, ZT3;       \
        vpshufb         SHFMSK, ZT4, ZT4;       \
        .else;\
        vpshufb         SHFMSK, ZT13, ZT1;       \
        vpshufb         SHFMSK, ZT14, ZT2;       \
        vpshufb         SHFMSK, ZT15, ZT3;       \
        vpshufb         SHFMSK, ZT16, ZT4;       \
        .endif; \
        vmovdqa64 ZT1, 0*64 + AESOUT_BLK_OFFSET(%rsp);  \
        vmovdqa64 ZT2, 1*64 + AESOUT_BLK_OFFSET(%rsp);       \
        vmovdqa64 ZT3, 2*64 + AESOUT_BLK_OFFSET(%rsp);       \
        vmovdqa64 ZT4, 3*64 + AESOUT_BLK_OFFSET(%rsp);       \
        .ifc DO_REDUCTION, final_reduction;     \
        .endif;

#define INITIAL_BLOCKS_Nx16(IN, OUT, KP, DATA_OFFSET, GHASH, CTR, CTR_CHECK, T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17, T18, T19, T20, T21, T22, GH, GL, GM, ADDBE_4x4, ADDBE_1234, SHUF_MASK, ENC_DEC, NBLOCKS, DEPTH_BLKi, NROUNDS) \
        vmovd           XWORD(CTR), DWORD(CTR_CHECK); \
        and             $255, DWORD(CTR_CHECK); \
        vshufi64x2      $0, CTR, CTR, CTR; \
        vpshufb         SHUF_MASK, CTR, CTR; \
        INITIAL_BLOCKS_16(IN, OUT, KP, DATA_OFFSET, GHASH, CTR, CTR_CHECK, ADDBE_4x4, ADDBE_1234, T0, T1, T2, T3, T4, T5, T6, T7, T8, SHUF_MASK, ENC_DEC, STACK_LOCAL_OFFSET, 0, NROUNDS) \
	INITIAL_BLOCKS_16(IN, OUT, KP, DATA_OFFSET, no_ghash, CTR, CTR_CHECK, ADDBE_4x4, ADDBE_1234, T0, T1, T2, T3, T4, T5, T6, T7, T8, SHUF_MASK, ENC_DEC, STACK_LOCAL_OFFSET + 256, 256, NROUNDS) \
	GHASH_16_ENCRYPT_16_PARALLEL(KP, OUT, IN, DATA_OFFSET, CTR, CTR_CHECK, HashKey_48, STACK_LOCAL_OFFSET + 512, STACK_LOCAL_OFFSET, SHUF_MASK, T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17, T18, T19, T20, T21, T22, ADDBE_4x4, ADDBE_1234, GL, GH, GM, first_time, ENC_DEC, 512, no_ghash_in, NROUNDS) \
	add             $(48 * 16), DATA_OFFSET;

#define GHASH_ENCRYPT_Nx16_PARALLEL(IN, OUT, GDATA_KEY, DATA_OFFSET, CTR_BE, SHFMSK, ZT0, ZT1, ZT2, ZT3, ZT4, ZT5, ZT6, ZT7, ZT8, ZT9, ZT10, ZT11, ZT12, ZT13, ZT14, ZT15, ZT16, ZT17, ZT18, ZT19, ZT20, ZT21, ZT22, GTH, GTL, GTM, ADDBE_4x4, ADDBE_1234, GHASH, ENC_DEC, NUM_BLOCKS, DEPTH_BLK, CTR_CHECK, NROUNDS)    \
	GHASH_16_ENCRYPT_16_PARALLEL(GDATA_KEY, OUT, IN, DATA_OFFSET, CTR_BE, CTR_CHECK, HashKey_32, STACK_LOCAL_OFFSET, STACK_LOCAL_OFFSET + (16 * 16), SHFMSK, ZT0, ZT1, ZT2, ZT3, ZT4, ZT5, ZT6, ZT7, ZT8, ZT9, ZT10, ZT11, ZT12, ZT13, ZT14, ZT15, ZT16, ZT17, ZT18, ZT19, ZT20, ZT21, ZT22, ADDBE_4x4, ADDBE_1234, GTL, GTH, GTM, no_reduction, ENC, 0, no_ghash_in, NROUNDS)       \
        GHASH_16_ENCRYPT_16_PARALLEL(GDATA_KEY, OUT, IN, DATA_OFFSET, CTR_BE, CTR_CHECK, HashKey_32 + 256, STACK_LOCAL_OFFSET + 256, STACK_LOCAL_OFFSET + (16 * 16) + 256, SHFMSK, ZT0, ZT1, ZT2, ZT3, ZT4, ZT5, ZT6, ZT7, ZT8, ZT9, ZT10, ZT11, ZT12, ZT13, ZT14, ZT15, ZT16, ZT17, ZT18, ZT19, ZT20, ZT21, ZT22, ADDBE_4x4, ADDBE_1234, GTL, GTH, GTM, final_reduction, ENC, 256, no_ghash_in, NROUNDS)       \
        vmovdqa64       ZT4, GHASH;             \
        GHASH_16_ENCRYPT_16_PARALLEL(GDATA_KEY, OUT, IN, DATA_OFFSET, CTR_BE, CTR_CHECK, HashKey_48, STACK_LOCAL_OFFSET + 512, STACK_LOCAL_OFFSET, SHFMSK, ZT0, ZT1, ZT2, ZT3, ZT4, ZT5, ZT6, ZT7, ZT8, ZT9, ZT10, ZT11, ZT12, ZT13, ZT14, ZT15, ZT16, ZT17, ZT18, ZT19, ZT20, ZT21, ZT22, ADDBE_4x4, ADDBE_1234, GTL, GTH, GTM, first_time, ENC, 512, GHASH, NROUNDS)  \
        add     $(NUM_BLOCKS * 16), DATA_OFFSET;        \

#define GHASH_LAST_Nx16(KP, GHASH, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, GH, GL,GM, LOOP_BLK, DEPTH_BLK)       \
        vmovdqa64       (((LOOP_BLK - DEPTH_BLK) * 16) + STACK_LOCAL_OFFSET)(%rsp), T13;       \
        vmovdqa64       (((LOOP_BLK - DEPTH_BLK) * 16) + 64 + STACK_LOCAL_OFFSET)(%rsp), T14;      \
        vmovdqu64       HashKey_32(KP), T15;    \
        vmovdqu64       HashKey_32 + 64(KP), T16;    \
        vpclmulqdq      $0x11, T15, T13, T1;    \
        vpclmulqdq      $0x00, T15, T13, T2;  \
        vpclmulqdq      $0x01, T15, T13, T3;  \
        vpclmulqdq      $0x10, T15, T13, T4;  \
        vpclmulqdq      $0x11, T16, T14, T5;  \
        vpclmulqdq      $0x00, T16, T14, T6;  \
        vpclmulqdq      $0x01, T16, T14, T7;  \
        vpclmulqdq      $0x10, T16, T14, T8;  \
        vpternlogq      $0x96, GH, T5, T1;      \
        vpternlogq      $0x96, GL, T6, T2;    \
        vpternlogq      $0x96, GM, T7, T3;    \
        vpxorq          T8, T4, T4;     \
        \
        vmovdqa64       (((LOOP_BLK - DEPTH_BLK) * 16) + STACK_LOCAL_OFFSET + 128)(%rsp), T13;      \
        vmovdqa64       (((LOOP_BLK - DEPTH_BLK) * 16) + 64 + STACK_LOCAL_OFFSET + 128)(%rsp), T14;      \
        vmovdqu64       HashKey_32 + 128(KP), T15;    \
        vmovdqu64       HashKey_32 + 64 + 128(KP), T16;    \
        vpclmulqdq      $0x11, T15, T13, T5;    \
        vpclmulqdq      $0x00, T15, T13, T6;  \
        vpclmulqdq      $0x01, T15, T13, T7;  \
        vpclmulqdq      $0x10, T15, T13, T8;  \
        vpclmulqdq      $0x11, T16, T14, T9;  \
        vpclmulqdq      $0x00, T16, T14, T10;  \
        vpclmulqdq      $0x01, T16, T14, T11;  \
        vpclmulqdq      $0x10, T16, T14, T12;  \
        vpternlogq      $0x96, T9, T5, T1;       \
        vpternlogq      $0x96, T10, T6, T2;    \
        vpternlogq      $0x96, T11, T7, T3;    \
        vpternlogq      $0x96, T12, T8, T4;    \
        \
        vmovdqa64       (((LOOP_BLK - DEPTH_BLK) * 16) + STACK_LOCAL_OFFSET + 256)(%rsp), T13;      \
        vmovdqa64       (((LOOP_BLK - DEPTH_BLK) * 16) + 64 + STACK_LOCAL_OFFSET + 256)(%rsp), T14;      \
        vmovdqu64       HashKey_32 + 256(KP), T15;    \
        vmovdqu64       HashKey_32 + 64 + 256(KP), T16;    \
        vpclmulqdq      $0x11, T15, T13, T5;    \
        vpclmulqdq      $0x00, T15, T13, T6;  \
        vpclmulqdq      $0x01, T15, T13, T7;  \
        vpclmulqdq      $0x10, T15, T13, T8;  \
        vpclmulqdq      $0x11, T16, T14, T9;  \
        vpclmulqdq      $0x00, T16, T14, T10;  \
        vpclmulqdq      $0x01, T16, T14, T11;  \
        vpclmulqdq      $0x10, T16, T14, T12;  \
        vpternlogq      $0x96, T9, T5, T1;       \
        vpternlogq      $0x96, T10, T6, T2;    \
        vpternlogq      $0x96, T11, T7, T3;    \
        vpternlogq      $0x96, T12, T8, T4;    \
        \
        vmovdqa64       (((LOOP_BLK - DEPTH_BLK) * 16) + STACK_LOCAL_OFFSET + 256 + 128)(%rsp), T13;      \
        vmovdqa64       (((LOOP_BLK - DEPTH_BLK) * 16) + 64 + STACK_LOCAL_OFFSET + 256 + 128)(%rsp), T14;      \
        vmovdqu64       HashKey_32 + 256 + 128(KP), T15;    \
        vmovdqu64       HashKey_32 + 64 + 256 + 128(KP), T16;    \
        vpclmulqdq      $0x11, T15, T13, T5;    \
        vpclmulqdq      $0x00, T15, T13, T6;  \
        vpclmulqdq      $0x01, T15, T13, T7;  \
        vpclmulqdq      $0x10, T15, T13, T8;  \
        vpclmulqdq      $0x11, T16, T14, T9;  \
        vpclmulqdq      $0x00, T16, T14, T10;  \
        vpclmulqdq      $0x01, T16, T14, T11;  \
        vpclmulqdq      $0x10, T16, T14, T12;  \
        vpternlogq      $0x96, T9, T5, T1;       \
        vpternlogq      $0x96, T10, T6, T2;    \
        vpternlogq      $0x96, T11, T7, T3;    \
        vpternlogq      $0x96, T12, T8, T4;    \
        vpxorq          T4, T3, T3;     \
        vpsrldq         $8, T3, T7;     \
        vpslldq         $8, T3, T8;     \
        vpxorq          T7, T1, T1;     \
        vpxorq          T8, T2, T2;     \
        \
        VHPXORI4x128(T1, T11)   \
        VHPXORI4x128(T2, T12)   \
        \
        vmovdqa64       POLY2(%rip), T15;       \
        VCLMUL_REDUCE(GHASH, T15, T1, T2, T3, T4);

#define ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16(NUM_BLOCKS, OPCODE, DST0, DST1, DST2, DST3, SRC1_0, SRC1_1, SRC1_2, SRC1_3, SRC2_0, SRC2_1, SRC2_2, SRC2_3) \
.set blocks_left,NUM_BLOCKS; \
.if NUM_BLOCKS < 4; \
	.if blocks_left == 1; \
		OPCODE        XWORD(SRC2_0), XWORD(SRC1_0), XWORD(DST0); \
	.elseif blocks_left == 2; \
        	OPCODE        YWORD(SRC2_0), YWORD(SRC1_0), YWORD(DST0); \
	.elseif blocks_left == 3; \
        	OPCODE        SRC2_0, SRC1_0, DST0; \
	.endif;	\
.elseif NUM_BLOCKS >= 4 && NUM_BLOCKS < 8;	\
	OPCODE	SRC2_0, SRC1_0, DST0;	\
	.set blocks_left, blocks_left - 4;	\
	.if blocks_left == 1; \
                OPCODE        XWORD(SRC2_1), XWORD(SRC1_1), XWORD(DST1); \
        .elseif blocks_left == 2; \
                OPCODE        YWORD(SRC2_1), YWORD(SRC1_1), YWORD(DST1); \
        .elseif blocks_left == 3; \
                OPCODE        SRC2_1, SRC1_1, DST1; \
        .endif; \
.elseif NUM_BLOCKS >= 8 && NUM_BLOCKS < 12;      \
        OPCODE  SRC2_0, SRC1_0, DST0;   \
        .set blocks_left, blocks_left - 4;      \
        OPCODE  SRC2_1, SRC1_1, DST1;   \
        .set blocks_left, blocks_left - 4;      \
        .if blocks_left == 1; \
                OPCODE        XWORD(SRC2_2), XWORD(SRC1_2), XWORD(DST2); \
        .elseif blocks_left == 2; \
                OPCODE        YWORD(SRC2_2), YWORD(SRC1_2), YWORD(DST2); \
        .elseif blocks_left == 3; \
                OPCODE        SRC2_2, SRC1_2, DST2; \
        .endif; \
.elseif NUM_BLOCKS >= 12 && NUM_BLOCKS < 16;      \
        OPCODE  SRC2_0, SRC1_0, DST0;   \
        .set blocks_left, blocks_left - 4;      \
	OPCODE  SRC2_1, SRC1_1, DST1;   \
        .set blocks_left, blocks_left - 4;      \
	OPCODE  SRC2_2, SRC1_2, DST2;   \
        .set blocks_left, blocks_left - 4;      \
        .if blocks_left == 1; \
                OPCODE        XWORD(SRC2_3), XWORD(SRC1_3), XWORD(DST3); \
        .elseif blocks_left == 2; \
                OPCODE        YWORD(SRC2_3), YWORD(SRC1_3), YWORD(DST3); \
        .elseif blocks_left == 3; \
                OPCODE        SRC2_3, SRC1_3, DST3; \
        .endif; \
.else;	\
	OPCODE  SRC2_0, SRC1_0, DST0;   \
        .set blocks_left, blocks_left - 4;      \
        OPCODE  SRC2_1, SRC1_1, DST1;   \
        .set blocks_left, blocks_left - 4;      \
        OPCODE  SRC2_2, SRC1_2, DST2;   \
        .set blocks_left, blocks_left - 4;      \
	OPCODE  SRC2_3, SRC1_3, DST3;   \
        .set blocks_left, blocks_left - 4;      \
.endif;	\

#define ZMM_LOAD_MASKED_BLOCKS_0_16(NUM_BLOCKS, INP, DATA_OFFSET, DST0, DST1, DST2, DST3, MASK) \
.set src_offset,0;	\
.set blocks_left, NUM_BLOCKS; \
.if NUM_BLOCKS <= 4; \
	.if blocks_left == 1; \
                vmovdqu8        src_offset(INP, DATA_OFFSET), XWORD(DST0){MASK}{z}; \
        .elseif blocks_left == 2; \
                vmovdqu8        src_offset(INP, DATA_OFFSET), YWORD(DST0){MASK}{z}; \
        .elseif (blocks_left == 3 || blocks_left == 4); \
                vmovdqu8        src_offset(INP, DATA_OFFSET), DST0{MASK}{z}; \
        .endif; \
.elseif NUM_BLOCKS > 4 && NUM_BLOCKS <= 8;	\
	vmovdqu8        src_offset(INP, DATA_OFFSET), DST0; \
	.set blocks_left, blocks_left - 4;	\
	.set src_offset, src_offset + 64;	\
	.if blocks_left == 1; \
                vmovdqu8        src_offset(INP, DATA_OFFSET), XWORD(DST1){MASK}{z}; \
        .elseif blocks_left == 2; \
                vmovdqu8        src_offset(INP, DATA_OFFSET), YWORD(DST1){MASK}{z}; \
        .elseif (blocks_left == 3 || blocks_left == 4); \
                vmovdqu8        src_offset(INP, DATA_OFFSET), DST1{MASK}{z}; \
        .endif; \
.elseif NUM_BLOCKS > 8 && NUM_BLOCKS <= 12;       \
	 vmovdqu8        src_offset(INP, DATA_OFFSET), DST0; \
        .set blocks_left, blocks_left - 4;      \
        .set src_offset, src_offset + 64;       \
	 vmovdqu8        src_offset(INP, DATA_OFFSET), DST1; \
        .set blocks_left, blocks_left - 4;      \
        .set src_offset, src_offset + 64;       \
	.if blocks_left == 1; \
                vmovdqu8        src_offset(INP, DATA_OFFSET), XWORD(DST2){MASK}{z}; \
        .elseif blocks_left == 2; \
                vmovdqu8        src_offset(INP, DATA_OFFSET), YWORD(DST2){MASK}{z}; \
        .elseif (blocks_left == 3 || blocks_left == 4); \
                vmovdqu8        src_offset(INP, DATA_OFFSET), DST2{MASK}{z}; \
        .endif; \
.else;	\
	 vmovdqu8        src_offset(INP, DATA_OFFSET), DST0; \
        .set blocks_left, blocks_left - 4;      \
        .set src_offset, src_offset + 64;       \
         vmovdqu8        src_offset(INP, DATA_OFFSET), DST1; \
        .set blocks_left, blocks_left - 4;      \
        .set src_offset, src_offset + 64;       \
	vmovdqu8        src_offset(INP, DATA_OFFSET), DST2; \
        .set blocks_left, blocks_left - 4;      \
        .set src_offset, src_offset + 64;       \
	.if blocks_left == 1; \
                vmovdqu8        src_offset(INP, DATA_OFFSET), XWORD(DST3){MASK}{z}; \
        .elseif blocks_left == 2; \
                vmovdqu8        src_offset(INP, DATA_OFFSET), YWORD(DST3){MASK}{z}; \
        .elseif (blocks_left == 3 || blocks_left == 4); \
                vmovdqu8        src_offset(INP, DATA_OFFSET), DST3{MASK}{z}; \
        .endif; \
.endif;	\

#define ZMM_AESENC_ROUND_BLOCKS_0_16(L0B0_3, L0B4_7, L0B8_11, L0B12_15, KEY, ROUND, D0_3, D4_7, D8_11, D12_15, NUMBL, NROUNDS) \
.if ROUND < 1; \
ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16(NUMBL, vpxorq, L0B0_3, L0B4_7, L0B8_11, L0B12_15, L0B0_3, L0B4_7, L0B8_11, L0B12_15, KEY, KEY, KEY, KEY) \
.endif; \
.if (ROUND >= 1) && (ROUND <= NROUNDS); \
ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16(NUMBL, vaesenc, L0B0_3, L0B4_7, L0B8_11, L0B12_15, L0B0_3, L0B4_7, L0B8_11, L0B12_15, KEY, KEY, KEY, KEY) \
.endif; \
.if ROUND > NROUNDS; \
ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16(NUMBL, vaesenclast, L0B0_3, L0B4_7, L0B8_11, L0B12_15, L0B0_3, L0B4_7, L0B8_11, L0B12_15, KEY, KEY, KEY, KEY) \
.ifnc D0_3, no_data; \
.ifnc D4_7, no_data; \
.ifnc D8_11, no_data; \
.ifnc D12_15, no_data; \
ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16(NUMBL, vpxorq, L0B0_3, L0B4_7, L0B8_11, L0B12_15, L0B0_3, L0B4_7, L0B8_11, L0B12_15, D0_3, D4_7, D8_11, D12_15) \
.endif; \
.endif; \
.endif; \
.endif; \
.endif;

#define ZMM_STORE_MASKED_BLOCKS_0_16(NUM_BLOCKS, OUTP, DATA_OFFSET, SRC0, SRC1, SRC2, SRC3, MASK) \
.set blocks_left, NUM_BLOCKS; \
.set dst_offset, 0;	\
.if NUM_BLOCKS <= 4; \
        .if blocks_left == 1; \
                vmovdqu8        XWORD(SRC0), dst_offset(OUTP, DATA_OFFSET){MASK}; \
        .elseif blocks_left == 2; \
                vmovdqu8        YWORD(SRC0), dst_offset(OUTP, DATA_OFFSET){MASK}; \
        .elseif (blocks_left == 3 || blocks_left == 4); \
                vmovdqu8        SRC0, dst_offset(OUTP, DATA_OFFSET){MASK}; \
        .endif; \
.elseif NUM_BLOCKS > 4 && NUM_BLOCKS <=8;       \
	vmovdqu8        SRC0, dst_offset(OUTP, DATA_OFFSET); \
        .set blocks_left, blocks_left - 4;      \
        .set dst_offset, dst_offset + 64;       \
	.if blocks_left == 1; \
                vmovdqu8        XWORD(SRC1), dst_offset(OUTP, DATA_OFFSET){MASK}; \
        .elseif blocks_left == 2; \
                vmovdqu8        YWORD(SRC1), dst_offset(OUTP, DATA_OFFSET){MASK}; \
        .elseif (blocks_left == 3 || blocks_left == 4); \
                vmovdqu8        SRC1, dst_offset(OUTP, DATA_OFFSET){MASK}; \
        .endif; \
.elseif NUM_BLOCKS > 8 && NUM_BLOCKS <= 12;       \
	vmovdqu8        SRC0, dst_offset(OUTP, DATA_OFFSET); \
        .set blocks_left, blocks_left - 4;      \
        .set dst_offset, dst_offset + 64;       \
	vmovdqu8        SRC1, dst_offset(OUTP, DATA_OFFSET); \
        .set blocks_left, blocks_left - 4;      \
        .set dst_offset, dst_offset + 64;       \
	.if blocks_left == 1; \
                vmovdqu8        XWORD(SRC2), dst_offset(OUTP, DATA_OFFSET){MASK}; \
        .elseif blocks_left == 2; \
                vmovdqu8        YWORD(SRC2), dst_offset(OUTP, DATA_OFFSET){MASK}; \
        .elseif (blocks_left == 3 || blocks_left == 4); \
                vmovdqu8        SRC2, dst_offset(OUTP, DATA_OFFSET){MASK}; \
        .endif; \
.else;	\
	vmovdqu8        SRC0, dst_offset(OUTP, DATA_OFFSET); \
        .set blocks_left, blocks_left - 4;      \
        .set dst_offset, dst_offset + 64;       \
        vmovdqu8        SRC1, dst_offset(OUTP, DATA_OFFSET); \
        .set blocks_left, blocks_left - 4;      \
        .set dst_offset, dst_offset + 64;       \
	vmovdqu8        SRC2, dst_offset(OUTP, DATA_OFFSET); \
        .set blocks_left, blocks_left - 4;      \
        .set dst_offset, dst_offset + 64;       \
	.if blocks_left == 1; \
                vmovdqu8        XWORD(SRC3), dst_offset(OUTP, DATA_OFFSET){MASK}; \
        .elseif blocks_left == 2; \
                vmovdqu8        YWORD(SRC3), dst_offset(OUTP, DATA_OFFSET){MASK}; \
        .elseif (blocks_left == 3 || blocks_left == 4); \
                vmovdqu8        SRC3, dst_offset(OUTP, DATA_OFFSET){MASK}; \
        .endif; \
.endif;

#define GHASH_1_TO_16(KP, GHASH, T1, T2, T3, T4, T5, T6, T7, T8, T9, GH, GL, GM, AAD_HASH_IN, CIPHER_IN0, CIPHER_IN1, CIPHER_IN2, CIPHER_IN3, NUM_BLOCKS, BOOL) \
.set	first_result, 1;	\
.set	reg_idx, 0;	\
.set	blocks_left, NUM_BLOCKS;	\
.if BOOL ==1;	\
.set    hashk, str1(HashKey_, NUM_BLOCKS);	\
.else;	\
.set    hashk, str1(HashKey_, NUM_BLOCKS)+ 0x11;      \
.endif;	\
	vpxorq          AAD_HASH_IN, CIPHER_IN0, CIPHER_IN0; \
.ifnc GH, no_zmm; \
.ifnc GL, no_zmm; \
.ifnc GM, no_zmm; \
	vmovdqa64       GH, T1; \
        vmovdqa64       GL, T2; \
        vmovdqa64       GM, T3; \
        vpxorq          T4, T4, T4; \
	.set		first_result, 0;	\
.endif; \
.endif; \
.endif; \
.if NUM_BLOCKS < 4;	\
	.if blocks_left == 1; \
		.if first_result == 1;	\
			vmovdqu64       hashk(KP), XWORD(T9); \
                        vpclmulqdq      $0x11, XWORD(T9), XWORD(CIPHER_IN0), XWORD(T1); \
                        vpclmulqdq      $0x00, XWORD(T9), XWORD(CIPHER_IN0), XWORD(T2); \
                        vpclmulqdq      $0x01, XWORD(T9), XWORD(CIPHER_IN0), XWORD(T3); \
                        vpclmulqdq      $0x10, XWORD(T9), XWORD(CIPHER_IN0), XWORD(T4); \
		.else;	\
			vmovdqu64       hashk(KP), XWORD(T9); \
                        vpclmulqdq      $0x11, XWORD(T9), XWORD(CIPHER_IN0), XWORD(T5); \
                        vpclmulqdq      $0x00, XWORD(T9), XWORD(CIPHER_IN0), XWORD(T6); \
                        vpclmulqdq      $0x01, XWORD(T9), XWORD(CIPHER_IN0), XWORD(T7); \
                        vpclmulqdq      $0x10, XWORD(T9), XWORD(CIPHER_IN0), XWORD(T8); \
		.endif;	\
	.elseif blocks_left == 2; \
		.if first_result == 1;  \
			vmovdqu64       hashk(KP), YWORD(T9); \
                        vpclmulqdq      $0x11, YWORD(T9), YWORD(CIPHER_IN0), YWORD(T1); \
                        vpclmulqdq      $0x00, YWORD(T9), YWORD(CIPHER_IN0), YWORD(T2); \
                        vpclmulqdq      $0x01, YWORD(T9), YWORD(CIPHER_IN0), YWORD(T3); \
                        vpclmulqdq      $0x10, YWORD(T9), YWORD(CIPHER_IN0), YWORD(T4); \
		.else;	\
			vmovdqu64       hashk(KP), YWORD(T9); \
                        vpclmulqdq      $0x11, YWORD(T9), YWORD(CIPHER_IN0), YWORD(T5); \
                        vpclmulqdq      $0x00, YWORD(T9), YWORD(CIPHER_IN0), YWORD(T6); \
                        vpclmulqdq      $0x01, YWORD(T9), YWORD(CIPHER_IN0), YWORD(T7); \
                        vpclmulqdq      $0x10, YWORD(T9), YWORD(CIPHER_IN0), YWORD(T8); \
		.endif;	\
	.elseif blocks_left == 3;	\
		.if first_result == 1;  \
                        vmovdqu64       hashk(KP), YWORD(T9); \
                        vinserti64x2    $2, 32 + hashk(KP), T9, T9; \
                        vpclmulqdq      $0x11, T9, CIPHER_IN0, T1; \
                        vpclmulqdq      $0x00, T9, CIPHER_IN0, T2; \
                        vpclmulqdq      $0x01, T9, CIPHER_IN0, T3; \
                        vpclmulqdq      $0x10, T9, CIPHER_IN0, T4; \
		.else;  \
			vmovdqu64       hashk(KP), YWORD(T9); \
                        vinserti64x2    $2, 32 + hashk(KP), T9, T9; \
                        vpclmulqdq      $0x11, T9, CIPHER_IN0, T5; \
                        vpclmulqdq      $0x00, T9, CIPHER_IN0, T6; \
                        vpclmulqdq      $0x01, T9, CIPHER_IN0, T7; \
                        vpclmulqdq      $0x10, T9, CIPHER_IN0, T8; \
		.endif;	\
	.endif;	\
	.if first_result != 1; \
                 vpxorq          T5, T1, T1; \
                 vpxorq          T6, T2, T2; \
                 vpxorq          T7, T3, T3; \
                 vpxorq          T8, T4, T4; \
        .endif; \
.elseif (NUM_BLOCKS >= 4) && (NUM_BLOCKS < 8); \
	vmovdqu64       hashk(KP), T9; \
	.if first_result == 1; \
                vpclmulqdq      $0x11, T9, CIPHER_IN0, T1; \
                vpclmulqdq      $0x00, T9, CIPHER_IN0, T2; \
                vpclmulqdq      $0x01, T9, CIPHER_IN0, T3; \
                vpclmulqdq      $0x10, T9, CIPHER_IN0, T4; \
                .set first_result, 0; \
        .else; \
                vpclmulqdq      $0x11, T9, CIPHER_IN0, T5; \
                vpclmulqdq      $0x00, T9, CIPHER_IN0, T6; \
                vpclmulqdq      $0x01, T9, CIPHER_IN0, T7; \
                vpclmulqdq      $0x10, T9, CIPHER_IN0, T8; \
                vpxorq          T5, T1, T1; \
                vpxorq          T6, T2, T2; \
                vpxorq          T7, T3, T3; \
                vpxorq          T8, T4, T4; \
        .endif; \
	.set hashk, hashk + 64; \
	.set blocks_left, blocks_left - 4;	\
	.set reg_idx, reg_idx + 1;	\
	.if blocks_left > 0;	\
	.if blocks_left == 1; \
                .if first_result == 1;  \
                        vmovdqu64       hashk(KP), XWORD(T9); \
                        vpclmulqdq      $0x11, XWORD(T9), XWORD(CIPHER_IN1), XWORD(T1); \
                        vpclmulqdq      $0x00, XWORD(T9), XWORD(CIPHER_IN1), XWORD(T2); \
                        vpclmulqdq      $0x01, XWORD(T9), XWORD(CIPHER_IN1), XWORD(T3); \
                        vpclmulqdq      $0x10, XWORD(T9), XWORD(CIPHER_IN1), XWORD(T4); \
                .else;  \
                        vmovdqu64       hashk(KP), XWORD(T9); \
                        vpclmulqdq      $0x11, XWORD(T9), XWORD(CIPHER_IN1), XWORD(T5); \
                        vpclmulqdq      $0x00, XWORD(T9), XWORD(CIPHER_IN1), XWORD(T6); \
                        vpclmulqdq      $0x01, XWORD(T9), XWORD(CIPHER_IN1), XWORD(T7); \
                        vpclmulqdq      $0x10, XWORD(T9), XWORD(CIPHER_IN1), XWORD(T8); \
                .endif; \
        .elseif blocks_left == 2; \
                .if first_result == 1;  \
                        vmovdqu64       hashk(KP), YWORD(T9); \
                        vpclmulqdq      $0x11, YWORD(T9), YWORD(CIPHER_IN1), YWORD(T1); \
                        vpclmulqdq      $0x00, YWORD(T9), YWORD(CIPHER_IN1), YWORD(T2); \
                        vpclmulqdq      $0x01, YWORD(T9), YWORD(CIPHER_IN1), YWORD(T3); \
                        vpclmulqdq      $0x10, YWORD(T9), YWORD(CIPHER_IN1), YWORD(T4); \
                .else;  \
                        vmovdqu64       hashk(KP), YWORD(T9); \
                        vpclmulqdq      $0x11, YWORD(T9), YWORD(CIPHER_IN1), YWORD(T5); \
                        vpclmulqdq      $0x00, YWORD(T9), YWORD(CIPHER_IN1), YWORD(T6); \
                        vpclmulqdq      $0x01, YWORD(T9), YWORD(CIPHER_IN1), YWORD(T7); \
                        vpclmulqdq      $0x10, YWORD(T9), YWORD(CIPHER_IN1), YWORD(T8); \
                .endif; \
        .elseif blocks_left == 3;  \
                .if first_result == 1;  \
                        vmovdqu64       hashk(KP), YWORD(T9); \
                        vinserti64x2    $2, 32 + hashk(KP), T9, T9; \
                        vpclmulqdq      $0x11, T9, CIPHER_IN1, T1; \
                        vpclmulqdq      $0x00, T9, CIPHER_IN1, T2; \
                        vpclmulqdq      $0x01, T9, CIPHER_IN1, T3; \
                        vpclmulqdq      $0x10, T9, CIPHER_IN1, T4; \
                .else;  \
                        vmovdqu64       hashk(KP), YWORD(T9); \
                        vinserti64x2    $2, 32 + hashk(KP), T9, T9; \
                        vpclmulqdq      $0x11, T9, CIPHER_IN1, T5; \
                        vpclmulqdq      $0x00, T9, CIPHER_IN1, T6; \
                        vpclmulqdq      $0x01, T9, CIPHER_IN1, T7; \
                        vpclmulqdq      $0x10, T9, CIPHER_IN1, T8; \
                .endif; \
        .endif; \
	.if first_result != 1; \
                        vpxorq          T5, T1, T1; \
                        vpxorq          T6, T2, T2; \
                        vpxorq          T7, T3, T3; \
                        vpxorq          T8, T4, T4; \
        .endif; \
	.endif;	\
.elseif (NUM_BLOCKS >= 8) && (NUM_BLOCKS < 12); \
        vmovdqu64       hashk(KP), T9; \
        .if first_result == 1; \
                vpclmulqdq      $0x11, T9, CIPHER_IN0, T1; \
                vpclmulqdq      $0x00, T9, CIPHER_IN0, T2; \
                vpclmulqdq      $0x01, T9, CIPHER_IN0, T3; \
                vpclmulqdq      $0x10, T9, CIPHER_IN0, T4; \
                .set first_result, 0; \
        .else; \
                vpclmulqdq      $0x11, T9, CIPHER_IN0, T5; \
                vpclmulqdq      $0x00, T9, CIPHER_IN0, T6; \
                vpclmulqdq      $0x01, T9, CIPHER_IN0, T7; \
                vpclmulqdq      $0x10, T9, CIPHER_IN0, T8; \
                vpxorq          T5, T1, T1; \
                vpxorq          T6, T2, T2; \
                vpxorq          T7, T3, T3; \
                vpxorq          T8, T4, T4; \
        .endif; \
        .set hashk, hashk + 64; \
        .set blocks_left, blocks_left - 4; \
	.set reg_idx, reg_idx + 1;      \
        vmovdqu64       hashk(KP), T9; \
        .if first_result == 1; \
                vpclmulqdq      $0x11, T9, CIPHER_IN1, T1; \
                vpclmulqdq      $0x00, T9, CIPHER_IN1, T2; \
                vpclmulqdq      $0x01, T9, CIPHER_IN1, T3; \
                vpclmulqdq      $0x10, T9, CIPHER_IN1, T4; \
                .set first_result, 0; \
        .else; \
                vpclmulqdq      $0x11, T9, CIPHER_IN1, T5; \
                vpclmulqdq      $0x00, T9, CIPHER_IN1, T6; \
                vpclmulqdq      $0x01, T9, CIPHER_IN1, T7; \
                vpclmulqdq      $0x10, T9, CIPHER_IN1, T8; \
                vpxorq          T5, T1, T1; \
                vpxorq          T6, T2, T2; \
                vpxorq          T7, T3, T3; \
                vpxorq          T8, T4, T4; \
        .endif; \
	.set hashk, hashk + 64; \
        .set blocks_left, blocks_left - 4; \
        .set reg_idx, reg_idx + 1;      \
	.if blocks_left > 0; \
	.if blocks_left == 1; \
                .if first_result == 1;  \
                        vmovdqu64       hashk(KP), XWORD(T9); \
                        vpclmulqdq      $0x11, XWORD(T9), XWORD(CIPHER_IN2), XWORD(T1); \
                        vpclmulqdq      $0x00, XWORD(T9), XWORD(CIPHER_IN2), XWORD(T2); \
                        vpclmulqdq      $0x01, XWORD(T9), XWORD(CIPHER_IN2), XWORD(T3); \
                        vpclmulqdq      $0x10, XWORD(T9), XWORD(CIPHER_IN2), XWORD(T4); \
                .else;  \
                        vmovdqu64       hashk(KP), XWORD(T9); \
                        vpclmulqdq      $0x11, XWORD(T9), XWORD(CIPHER_IN2), XWORD(T5); \
                        vpclmulqdq      $0x00, XWORD(T9), XWORD(CIPHER_IN2), XWORD(T6); \
                        vpclmulqdq      $0x01, XWORD(T9), XWORD(CIPHER_IN2), XWORD(T7); \
                        vpclmulqdq      $0x10, XWORD(T9), XWORD(CIPHER_IN2), XWORD(T8); \
                .endif; \
        .elseif blocks_left == 2; \
                .if first_result == 1;  \
                        vmovdqu64       hashk(KP), YWORD(T9); \
                        vpclmulqdq      $0x11, YWORD(T9), YWORD(CIPHER_IN2), YWORD(T1); \
                        vpclmulqdq      $0x00, YWORD(T9), YWORD(CIPHER_IN2), YWORD(T2); \
                        vpclmulqdq      $0x01, YWORD(T9), YWORD(CIPHER_IN2), YWORD(T3); \
                        vpclmulqdq      $0x10, YWORD(T9), YWORD(CIPHER_IN2), YWORD(T4); \
                .else;  \
                        vmovdqu64       hashk(KP), YWORD(T9); \
                        vpclmulqdq      $0x11, YWORD(T9), YWORD(CIPHER_IN2), YWORD(T5); \
                        vpclmulqdq      $0x00, YWORD(T9), YWORD(CIPHER_IN2), YWORD(T6); \
                        vpclmulqdq      $0x01, YWORD(T9), YWORD(CIPHER_IN2), YWORD(T7); \
                        vpclmulqdq      $0x10, YWORD(T9), YWORD(CIPHER_IN2), YWORD(T8); \
                .endif; \
        .elseif blocks_left == 3;  \
                .if first_result == 1;  \
                        vmovdqu64       hashk(KP), YWORD(T9); \
                        vinserti64x2    $2, 32 + hashk(KP), T9, T9; \
                        vpclmulqdq      $0x11, T9, CIPHER_IN2, T1; \
                        vpclmulqdq      $0x00, T9, CIPHER_IN2, T2; \
                        vpclmulqdq      $0x01, T9, CIPHER_IN2, T3; \
                        vpclmulqdq      $0x10, T9, CIPHER_IN2, T4; \
                .else;  \
                        vmovdqu64       hashk(KP), YWORD(T9); \
                        vinserti64x2    $2, 32 + hashk(KP), T9, T9; \
                        vpclmulqdq      $0x11, T9, CIPHER_IN2, T5; \
                        vpclmulqdq      $0x00, T9, CIPHER_IN2, T6; \
                        vpclmulqdq      $0x01, T9, CIPHER_IN2, T7; \
                        vpclmulqdq      $0x10, T9, CIPHER_IN2, T8; \
                .endif; \
        .endif; \
        .if first_result != 1; \
                vpxorq          T5, T1, T1; \
                vpxorq          T6, T2, T2; \
                vpxorq          T7, T3, T3; \
                vpxorq          T8, T4, T4; \
        .endif; \
	.endif;	\
.elseif (NUM_BLOCKS >= 12) && (NUM_BLOCKS < 16); \
        vmovdqu64       hashk(KP), T9; \
        .if first_result == 1; \
                vpclmulqdq      $0x11, T9, CIPHER_IN0, T1; \
                vpclmulqdq      $0x00, T9, CIPHER_IN0, T2; \
                vpclmulqdq      $0x01, T9, CIPHER_IN0, T3; \
                vpclmulqdq      $0x10, T9, CIPHER_IN0, T4; \
                first_result = 0; \
        .else; \
                vpclmulqdq      $0x11, T9, CIPHER_IN0, T5; \
                vpclmulqdq      $0x00, T9, CIPHER_IN0, T6; \
                vpclmulqdq      $0x01, T9, CIPHER_IN0, T7; \
                vpclmulqdq      $0x10, T9, CIPHER_IN0, T8; \
                vpxorq          T5, T1, T1; \
                vpxorq          T6, T2, T2; \
                vpxorq          T7, T3, T3; \
                vpxorq          T8, T4, T4; \
        .endif; \
	.set hashk, hashk + 64; \
        .set blocks_left, blocks_left - 4; \
        .set reg_idx, reg_idx + 1;      \
        vmovdqu64       hashk(KP), T9; \
        .if first_result == 1; \
                vpclmulqdq      $0x11, T9, CIPHER_IN1, T1; \
                vpclmulqdq      $0x00, T9, CIPHER_IN1, T2; \
                vpclmulqdq      $0x01, T9, CIPHER_IN1, T3; \
                vpclmulqdq      $0x10, T9, CIPHER_IN1, T4; \
                first_result = 0; \
        .else; \
                vpclmulqdq      $0x11, T9, CIPHER_IN1, T5; \
                vpclmulqdq      $0x00, T9, CIPHER_IN1, T6; \
                vpclmulqdq      $0x01, T9, CIPHER_IN1, T7; \
                vpclmulqdq      $0x10, T9, CIPHER_IN1, T8; \
                vpxorq          T5, T1, T1; \
                vpxorq          T6, T2, T2; \
                vpxorq          T7, T3, T3; \
                vpxorq          T8, T4, T4; \
        .endif; \
	.set hashk, hashk + 64; \
        .set blocks_left, blocks_left - 4; \
        .set reg_idx, reg_idx + 1;      \
        vmovdqu64       hashk(KP), T9; \
        .if first_result == 1; \
                vpclmulqdq      $0x11, T9, CIPHER_IN2, T1; \
                vpclmulqdq      $0x00, T9, CIPHER_IN2, T2; \
                vpclmulqdq      $0x01, T9, CIPHER_IN2, T3; \
                vpclmulqdq      $0x10, T9, CIPHER_IN2, T4; \
                first_result = 0; \
        .else; \
                vpclmulqdq      $0x11, T9, CIPHER_IN2, T5; \
                vpclmulqdq      $0x00, T9, CIPHER_IN2, T6; \
                vpclmulqdq      $0x01, T9, CIPHER_IN2, T7; \
                vpclmulqdq      $0x10, T9, CIPHER_IN2, T8; \
                vpxorq          T5, T1, T1; \
                vpxorq          T6, T2, T2; \
                vpxorq          T7, T3, T3; \
                vpxorq          T8, T4, T4; \
        .endif; \
	.set hashk, hashk + 64; \
        .set blocks_left, blocks_left - 4; \
        .set reg_idx, reg_idx + 1;      \
	.if blocks_left > 0;	\
        .if blocks_left == 1; \
                .if first_result == 1;  \
                        vmovdqu64       hashk(KP), XWORD(T9); \
                        vpclmulqdq      $0x11, XWORD(T9), XWORD(CIPHER_IN3), XWORD(T1); \
                        vpclmulqdq      $0x00, XWORD(T9), XWORD(CIPHER_IN3), XWORD(T2); \
                        vpclmulqdq      $0x01, XWORD(T9), XWORD(CIPHER_IN3), XWORD(T3); \
                        vpclmulqdq      $0x10, XWORD(T9), XWORD(CIPHER_IN3), XWORD(T4); \
                .else;  \
                        vmovdqu64       hashk(KP), XWORD(T9); \
                        vpclmulqdq      $0x11, XWORD(T9), XWORD(CIPHER_IN3), XWORD(T5); \
                        vpclmulqdq      $0x00, XWORD(T9), XWORD(CIPHER_IN3), XWORD(T6); \
                        vpclmulqdq      $0x01, XWORD(T9), XWORD(CIPHER_IN3), XWORD(T7); \
                        vpclmulqdq      $0x10, XWORD(T9), XWORD(CIPHER_IN3), XWORD(T8); \
                .endif; \
        .elseif blocks_left == 2; \
                .if first_result == 1;  \
                        vmovdqu64       hashk(KP), YWORD(T9); \
                        vpclmulqdq      $0x11, YWORD(T9), YWORD(CIPHER_IN3), YWORD(T1); \
                        vpclmulqdq      $0x00, YWORD(T9), YWORD(CIPHER_IN3), YWORD(T2); \
                        vpclmulqdq      $0x01, YWORD(T9), YWORD(CIPHER_IN3), YWORD(T3); \
                        vpclmulqdq      $0x10, YWORD(T9), YWORD(CIPHER_IN3), YWORD(T4); \
                .else;  \
                        vmovdqu64       hashk(KP), YWORD(T9); \
                        vpclmulqdq      $0x11, YWORD(T9), YWORD(CIPHER_IN3), YWORD(T5); \
                        vpclmulqdq      $0x00, YWORD(T9), YWORD(CIPHER_IN3), YWORD(T6); \
                        vpclmulqdq      $0x01, YWORD(T9), YWORD(CIPHER_IN3), YWORD(T7); \
                        vpclmulqdq      $0x10, YWORD(T9), YWORD(CIPHER_IN3), YWORD(T8); \
                .endif; \
        .elseif blocks_left == 3;  \
                .if first_result == 1;  \
                        vmovdqu64       hashk(KP), YWORD(T9); \
                        vinserti64x2    $2, 32 + hashk(KP), T9, T9; \
                        vpclmulqdq      $0x11, T9, CIPHER_IN3, T1; \
                        vpclmulqdq      $0x00, T9, CIPHER_IN3, T2; \
                        vpclmulqdq      $0x01, T9, CIPHER_IN3, T3; \
                        vpclmulqdq      $0x10, T9, CIPHER_IN3, T4; \
                .else;  \
                        vmovdqu64       hashk(KP), YWORD(T9); \
                        vinserti64x2    $2, 32 + hashk(KP), T9, T9; \
                        vpclmulqdq      $0x11, T9, CIPHER_IN3, T5; \
                        vpclmulqdq      $0x00, T9, CIPHER_IN3, T6; \
                        vpclmulqdq      $0x01, T9, CIPHER_IN3, T7; \
                        vpclmulqdq      $0x10, T9, CIPHER_IN3, T8; \
                .endif; \
        .endif; \
        .if first_result != 1; \
                        vpxorq          T5, T1, T1; \
                        vpxorq          T6, T2, T2; \
                        vpxorq          T7, T3, T3; \
                        vpxorq          T8, T4, T4; \
        .endif; \
	.endif;	\
.else;	\
	vmovdqu64       hashk(KP), T9; \
        .if first_result == 1; \
                vpclmulqdq      $0x11, T9, CIPHER_IN0, T1; \
                vpclmulqdq      $0x00, T9, CIPHER_IN0, T2; \
                vpclmulqdq      $0x01, T9, CIPHER_IN0, T3; \
                vpclmulqdq      $0x10, T9, CIPHER_IN0, T4; \
                first_result = 0; \
        .else; \
                vpclmulqdq      $0x11, T9, CIPHER_IN0, T5; \
                vpclmulqdq      $0x00, T9, CIPHER_IN0, T6; \
                vpclmulqdq      $0x01, T9, CIPHER_IN0, T7; \
                vpclmulqdq      $0x10, T9, CIPHER_IN0, T8; \
                vpxorq          T5, T1, T1; \
                vpxorq          T6, T2, T2; \
                vpxorq          T7, T3, T3; \
                vpxorq          T8, T4, T4; \
        .endif; \
        .set hashk, hashk + 64; \
        .set blocks_left, blocks_left - 4; \
        .set reg_idx, reg_idx + 1;     \
	vmovdqu64       hashk(KP), T9; \
        .if first_result == 1; \
                vpclmulqdq      $0x11, T9, CIPHER_IN1, T1; \
                vpclmulqdq      $0x00, T9, CIPHER_IN1, T2; \
                vpclmulqdq      $0x01, T9, CIPHER_IN1, T3; \
                vpclmulqdq      $0x10, T9, CIPHER_IN1, T4; \
                first_result = 0; \
        .else; \
                vpclmulqdq      $0x11, T9, CIPHER_IN1, T5; \
                vpclmulqdq      $0x00, T9, CIPHER_IN1, T6; \
                vpclmulqdq      $0x01, T9, CIPHER_IN1, T7; \
                vpclmulqdq      $0x10, T9, CIPHER_IN1, T8; \
                vpxorq          T5, T1, T1; \
                vpxorq          T6, T2, T2; \
                vpxorq          T7, T3, T3; \
                vpxorq          T8, T4, T4; \
        .endif; \
        .set hashk, hashk + 64; \
        .set blocks_left, blocks_left - 4; \
        .set reg_idx, reg_idx + 1;      \
        vmovdqu64       hashk(KP), T9; \
        .if first_result == 1; \
                vpclmulqdq      $0x11, T9, CIPHER_IN2, T1; \
                vpclmulqdq      $0x00, T9, CIPHER_IN2, T2; \
                vpclmulqdq      $0x01, T9, CIPHER_IN2, T3; \
                vpclmulqdq      $0x10, T9, CIPHER_IN2, T4; \
                first_result = 0; \
        .else; \
                vpclmulqdq      $0x11, T9, CIPHER_IN2, T5; \
                vpclmulqdq      $0x00, T9, CIPHER_IN2, T6; \
                vpclmulqdq      $0x01, T9, CIPHER_IN2, T7; \
                vpclmulqdq      $0x10, T9, CIPHER_IN2, T8; \
                vpxorq          T5, T1, T1; \
                vpxorq          T6, T2, T2; \
                vpxorq          T7, T3, T3; \
                vpxorq          T8, T4, T4; \
        .endif; \
        .set hashk, hashk + 64; \
        .set blocks_left, blocks_left - 4; \
        .set reg_idx, reg_idx + 1;      \
	vmovdqu64       hashk(KP), T9; \
        .if first_result == 1; \
                vpclmulqdq      $0x11, T9, CIPHER_IN3, T1; \
                vpclmulqdq      $0x00, T9, CIPHER_IN3, T2; \
                vpclmulqdq      $0x01, T9, CIPHER_IN3, T3; \
                vpclmulqdq      $0x10, T9, CIPHER_IN3, T4; \
                first_result = 0; \
        .else; \
                vpclmulqdq      $0x11, T9, CIPHER_IN3, T5; \
                vpclmulqdq      $0x00, T9, CIPHER_IN3, T6; \
                vpclmulqdq      $0x01, T9, CIPHER_IN3, T7; \
                vpclmulqdq      $0x10, T9, CIPHER_IN3, T8; \
                vpxorq          T5, T1, T1; \
                vpxorq          T6, T2, T2; \
                vpxorq          T7, T3, T3; \
                vpxorq          T8, T4, T4; \
        .endif; \
        .set hashk, hashk + 64; \
        .set blocks_left, blocks_left - 4; \
        .set reg_idx, reg_idx + 1;      \
.endif;	\
vpxorq          T4, T3, T3; \
vpsrldq         $8, T3, T7; \
vpslldq         $8, T3, T8; \
vpxorq          T7, T1, T1; \
vpxorq          T8, T2, T2; \
VHPXORI4x128(T1, T7); \
VHPXORI4x128(T2, T8); \
vmovdqa64       POLY2(%rip), XWORD(T9); \
VCLMUL_REDUCE(XWORD(GHASH), XWORD(T9), XWORD(T1), XWORD(T2), XWORD(T3), XWORD(T4));
		
#define INITIAL_BLOCKS_PARTIAL(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, LENGTH, DATA_OFFSET, num_initial_blocks, CTR, HASH_IN_OUT, ENC_DEC, INSTANCE_TYPE, ZT0, ZT1, ZT2, ZT3, ZT4, ZT5, ZT6, ZT7, ZT8, ZT9, ZT10, ZT11, ZT12, ZT13, ZT14, ZT15, ZT16, ZT17, ZT18, ZT19, ZT20, ZT21, ZT22, GH, GL, GM, IA0, IA1, MASKREG, SHUFMASK, NROUNDS) \
.ifnc GH, no_zmm; \
.ifnc GL, no_zmm; \
.ifnc GM, no_zmm; \
    vpxorq          HASH_IN_OUT, HASH_IN_OUT, HASH_IN_OUT; \
.endif; \
.endif; \
.endif; \
    vmovdqa64       HASH_IN_OUT, XWORD(ZT2); \
.if num_initial_blocks == 1; \
        vpaddd          ONE(%rip), CTR, XWORD(ZT3); \
.elseif num_initial_blocks == 2; \
        vshufi64x2      $0, YWORD(CTR), YWORD(CTR), YWORD(ZT3); \
        vpaddd          ddq_add_1234(%rip), YWORD(ZT3), YWORD(ZT3); \
.else; \
        vshufi64x2      $0, ZWORD(CTR), ZWORD(CTR), ZWORD(CTR); \
        vpaddd          ddq_add_1234(%rip), ZWORD(CTR), ZT3; \
.if num_initial_blocks > 4; \
        vpaddd          ddq_add_5678(%rip), ZWORD(CTR), ZT4; \
.endif; \
.if num_initial_blocks > 8; \
        vpaddd          ddq_add_8888(%rip), ZT3, ZT8; \
.endif; \
.if num_initial_blocks > 12; \
        vpaddd          ddq_add_8888(%rip), ZT4, ZT9; \
.endif; \
.endif; \
        lea             byte64_len_to_mask_table(%rip), IA0; \
        mov             LENGTH, IA1; \
.if num_initial_blocks > 12; \
        sub             $(3 * 64), IA1; \
.elseif num_initial_blocks > 8; \
        sub             $(2 * 64), IA1; \
.elseif num_initial_blocks > 4; \
        sub             $64, IA1; \
.endif; \
        kmovq           (IA0, IA1, 8), MASKREG; \
.if num_initial_blocks <= 4; \
        vextracti32x4   $(num_initial_blocks - 1), ZT3, CTR; \
.elseif num_initial_blocks <= 8; \
        vextracti32x4   $(num_initial_blocks - 5), ZT4, CTR; \
.elseif num_initial_blocks <= 12; \
        vextracti32x4   $(num_initial_blocks - 9), ZT8, CTR; \
.else; \
        vextracti32x4   $(num_initial_blocks - 13), ZT9, CTR; \
.endif; \
ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16(num_initial_blocks, vpshufb, ZT3, ZT4, ZT8, ZT9, ZT3, ZT4, ZT8, ZT9, SHUFMASK, SHUFMASK, SHUFMASK, SHUFMASK) \
ZMM_LOAD_MASKED_BLOCKS_0_16(num_initial_blocks, PLAIN_CYPH_IN, DATA_OFFSET, ZT5, ZT6, ZT10, ZT11, MASKREG) \
.if NROUNDS ==9;	\
vbroadcastf64x2 (GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 0, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*1(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 1, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*2(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 2, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*3(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 3, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*4(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 4, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*5(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 5, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*6(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 6, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*7(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 7, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*8(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 8, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*9(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 9, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*10(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 10, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
.elseif NROUNDS == 11;	\
vbroadcastf64x2 (GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 0, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*1(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 1, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*2(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 2, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*3(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 3, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*4(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 4, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*5(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 5, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*6(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 6, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*7(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 7, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*8(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 8, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*9(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 9, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*10(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 10, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*11(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 11, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*12(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 12, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
.elseif NROUNDS == 13;	\
vbroadcastf64x2 (GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 0, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*1(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 1, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*2(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 2, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*3(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 3, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*4(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 4, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*5(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 5, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*6(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 6, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*7(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 7, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*8(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 8, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*9(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 9, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*10(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 10, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*11(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 11, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*12(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 12, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*13(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 13, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
vbroadcastf64x2 16*14(GDATA_KEY), ZT1; \
ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, ZT8, ZT9, ZT1, 14, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, NROUNDS) \
.endif;	\
.if num_initial_blocks <= 4; \
        vextracti32x4   $(num_initial_blocks - 1), ZT3, XWORD(ZT1); \
.elseif num_initial_blocks <= 8; \
        vextracti32x4   $(num_initial_blocks - 5), ZT4, XWORD(ZT1); \
.elseif num_initial_blocks <= 12; \
        vextracti32x4   $(num_initial_blocks - 9), ZT8, XWORD(ZT1); \
.else; \
        vextracti32x4   $(num_initial_blocks - 13), ZT9, XWORD(ZT1); \
.endif; \
ZMM_STORE_MASKED_BLOCKS_0_16(num_initial_blocks, CYPH_PLAIN_OUT,DATA_OFFSET, ZT3, ZT4, ZT8, ZT9, MASKREG) \
.if num_initial_blocks <= 4; \
        vmovdqu8        ZT3, ZT3{MASKREG}{z}; \
.elseif num_initial_blocks <= 8; \
        vmovdqu8        ZT4, ZT4{MASKREG}{z}; \
.elseif num_initial_blocks <= 12; \
        vmovdqu8        ZT8, ZT8{MASKREG}{z}; \
.else; \
        vmovdqu8        ZT9, ZT9{MASKREG}{z}; \
.endif; \
.ifc  ENC_DEC, DEC; \
        ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16(num_initial_blocks, vpshufb, \
                        ZT5, ZT6, ZT10, ZT11, \
                        ZT5, ZT6, ZT10, ZT11, \
                        SHUFMASK, SHUFMASK, SHUFMASK, SHUFMASK) \
.else; \
         ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16(num_initial_blocks, vpshufb, \
                        ZT5, ZT6, ZT10, ZT11, \
                        ZT3, ZT4, ZT8, ZT9, \
                        SHUFMASK, SHUFMASK, SHUFMASK, SHUFMASK) \
.endif; \
.if num_initial_blocks <= 4; \
        vextracti32x4   $(num_initial_blocks - 1), ZT5, XWORD(ZT7); \
.elseif num_initial_blocks <= 8; \
        vextracti32x4   $(num_initial_blocks - 5), ZT6, XWORD(ZT7); \
.elseif num_initial_blocks <= 12; \
        vextracti32x4   $(num_initial_blocks - 9), ZT10, XWORD(ZT7); \
.else; \
        vextracti32x4   $(num_initial_blocks - 13), ZT11, XWORD(ZT7); \
.endif; \
.if num_initial_blocks > 1; \
        add     $(16 * (num_initial_blocks - 1)), DATA_OFFSET; \
        sub     $(16 * (num_initial_blocks - 1)), LENGTH; \
.endif; \
.if num_initial_blocks < 16; \
        cmp     $16, LENGTH; \
        jl      1f; \
        sub     $16, LENGTH; \
        add     $16, DATA_OFFSET; \
        mov     LENGTH, PBlockLen(GDATA_CTX); \
        GHASH_1_TO_16(GDATA_KEY, HASH_IN_OUT, ZT12, ZT13, ZT14, ZT15, ZT16, ZT17, ZT18, ZT19, ZT20, GH, GL, GM, ZT2, ZT5, ZT6, ZT10, ZT11, num_initial_blocks,1) \
	jmp     2f; \
.endif;	\
1:;	\
	mov     LENGTH, PBlockLen(GDATA_CTX); \
	vmovdqu64       XWORD(ZT1), PBlockEncKey(GDATA_CTX); \
.ifc INSTANCE_TYPE, multi_call;	\
	.if num_initial_blocks > 1; \
		GHASH_1_TO_16(GDATA_KEY, HASH_IN_OUT, ZT12, ZT13, ZT14, ZT15, ZT16, ZT17, ZT18, ZT19, ZT20, GH, GL, GM, ZT2, ZT5, ZT6, ZT10, ZT11, num_initial_blocks - 1, 0) \
	.else;	\
		.ifc GH, no_zmm; \
		.ifc GL, no_zmm; \
        	.ifc GM, no_zmm; \
			vpxorq          XWORD(ZT7), XWORD(ZT2), HASH_IN_OUT; \
		.else;		\
			vpsrldq         $8, GM, ZT12; \
	        	vpslldq         $8, GM, ZT13; \
	        	vpxorq          ZT12, GH, GH; \
			vpxorq          ZT13, GL, GL; \
	        	VHPXORI4x128(GH, ZT12) \
		        VHPXORI4x128(GL, ZT13) \
		        vmovdqa64       POLY2(%rip), XWORD(ZT12); \
	        	VCLMUL_REDUCE(HASH_IN_OUT, XWORD(ZT12), XWORD(GH), XWORD(GL), XWORD(ZT13), XWORD(ZT14)) \
		        vpxorq          XWORD(ZT7), HASH_IN_OUT, HASH_IN_OUT; \
		.endif; \
		.endif; \
		.endif; \
		jmp             3f; \
	.endif;	\
.else;	\
	.if num_initial_blocks > 0; \
                GHASH_1_TO_16(GDATA_KEY, HASH_IN_OUT, ZT12, ZT13, ZT14, ZT15, ZT16, ZT17, ZT18, ZT19, ZT20, GH, GL, GM, ZT2, ZT5, ZT6, ZT10, ZT11, num_initial_blocks, 1) \
	.else;	\
		.ifc GH, no_zmm; \
                .ifc GL, no_zmm; \
                .ifc GM, no_zmm; \
                        vpxorq          XWORD(ZT7), XWORD(ZT2), HASH_IN_OUT; \
                .else;          \
                        vpsrldq         $8, GM, ZT12; \
                        vpslldq         $8, GM, ZT13; \
                        vpxorq          ZT12, GH, GH; \
                        vpxorq          ZT13, GL, GL; \
                        VHPXORI4x128(GH, ZT12) \
                        VHPXORI4x128(GL, ZT13) \
                        vmovdqa64       POLY2(%rip), XWORD(ZT12); \
                        VCLMUL_REDUCE(HASH_IN_OUT, XWORD(ZT12), XWORD(GH), XWORD(GL), XWORD(ZT13), XWORD(ZT14)) \
                        vpxorq          XWORD(ZT7), HASH_IN_OUT, HASH_IN_OUT; \
                .endif; \
                .endif; \
                .endif; \
		jmp             3f; \
	.endif;	\
.endif; \
2:;	\
    .ifc INSTANCE_TYPE, multi_call; \
    .if num_initial_blocks > 1; \
    .if num_initial_blocks != 16; \
    or              LENGTH, LENGTH; \
    je              3f; \
    .endif; \
    vpxorq          XWORD(ZT7), HASH_IN_OUT, HASH_IN_OUT; \
    .endif; \
    .endif; \
3:;	\

#define  GCM_ENC_DEC_SMALL(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, PLAIN_CYPH_LEN, ENC_DEC, DATA_OFFSET, LENGTH, NUM_BLOCKS, CTR, HASH_IN_OUT, INSTANCE_TYPE, ZTMP0, ZTMP1, ZTMP2, ZTMP3, ZTMP4, ZTMP5, ZTMP6, ZTMP7, ZTMP8, ZTMP9, ZTMP10, ZTMP11, ZTMP12, ZTMP13, ZTMP14, ZTMP15, ZTMP16, ZTMP17, ZTMP18, ZTMP19, ZTMP20, ZTMP21, ZTMP22, GH, GL, GM, IA0, IA1, MASKREG, SHUFMASK, NROUNDS) \
        cmp     $8, NUM_BLOCKS; \
        je      8f; \
        jl      18f; \
        cmp     $12, NUM_BLOCKS; \
        je      12f; \
        jl      17f; \
        cmp     $16, NUM_BLOCKS; \
        je      16f; \
        cmp     $15, NUM_BLOCKS; \
        je      15f; \
        cmp     $14, NUM_BLOCKS; \
        je      14f; \
        jmp     13f; \
17:; \
        cmp     $11, NUM_BLOCKS; \
        je      11f; \
        cmp     $10, NUM_BLOCKS; \
        je      10f; \
        jmp     9f; \
18:; \
        cmp     $4, NUM_BLOCKS; \
        je      4f; \
        jl      19f; \
        cmp     $7, NUM_BLOCKS; \
        je      7f; \
        cmp     $6, NUM_BLOCKS; \
        je      6f; \
        jmp     5f; \
19:; \
        cmp     $3, NUM_BLOCKS; \
        je      28f; \
        cmp     $2, NUM_BLOCKS; \
        je      27f; \
1:;     \
        INITIAL_BLOCKS_PARTIAL(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, LENGTH, DATA_OFFSET, 1, CTR, HASH_IN_OUT, ENC_DEC, INSTANCE_TYPE, ZTMP0, ZTMP1, ZTMP2, ZTMP3, ZTMP4, ZTMP5, ZTMP6, ZTMP7, ZTMP8, ZTMP9, ZTMP10, ZTMP11, ZTMP12, ZTMP13, ZTMP14, ZTMP15, ZTMP16, ZTMP17, ZTMP18, ZTMP19, ZTMP20, ZTMP21, ZTMP22, GH, GL, GM, IA0, IA1, MASKREG, SHUFMASK, NROUNDS) \
        jmp     20f;        \
27:;     \
        INITIAL_BLOCKS_PARTIAL(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, LENGTH, DATA_OFFSET, 2, CTR, HASH_IN_OUT, ENC_DEC, INSTANCE_TYPE, ZTMP0, ZTMP1, ZTMP2, ZTMP3, ZTMP4, ZTMP5, ZTMP6, ZTMP7, ZTMP8, ZTMP9, ZTMP10, ZTMP11, ZTMP12, ZTMP13, ZTMP14, ZTMP15, ZTMP16, ZTMP17, ZTMP18, ZTMP19, ZTMP20, ZTMP21, ZTMP22, GH, GL, GM, IA0, IA1, MASKREG, SHUFMASK, NROUNDS) \
        jmp     20f;        \
28:;     \
        INITIAL_BLOCKS_PARTIAL(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, LENGTH, DATA_OFFSET, 3, CTR, HASH_IN_OUT, ENC_DEC, INSTANCE_TYPE, ZTMP0, ZTMP1, ZTMP2, ZTMP3, ZTMP4, ZTMP5, ZTMP6, ZTMP7, ZTMP8, ZTMP9, ZTMP10, ZTMP11, ZTMP12, ZTMP13, ZTMP14, ZTMP15, ZTMP16, ZTMP17, ZTMP18, ZTMP19, ZTMP20, ZTMP21, ZTMP22, GH, GL, GM, IA0, IA1, MASKREG, SHUFMASK, NROUNDS) \
        jmp     20f;        \
4:;     \
        INITIAL_BLOCKS_PARTIAL(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, LENGTH, DATA_OFFSET, 4, CTR, HASH_IN_OUT, ENC_DEC, INSTANCE_TYPE, ZTMP0, ZTMP1, ZTMP2, ZTMP3, ZTMP4, ZTMP5, ZTMP6, ZTMP7, ZTMP8, ZTMP9, ZTMP10, ZTMP11, ZTMP12, ZTMP13, ZTMP14, ZTMP15, ZTMP16, ZTMP17, ZTMP18, ZTMP19, ZTMP20, ZTMP21, ZTMP22, GH, GL, GM, IA0, IA1, MASKREG, SHUFMASK, NROUNDS) \
        jmp     20f;        \
5:;     \
        INITIAL_BLOCKS_PARTIAL(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, LENGTH, DATA_OFFSET, 5, CTR, HASH_IN_OUT, ENC_DEC, INSTANCE_TYPE, ZTMP0, ZTMP1, ZTMP2, ZTMP3, ZTMP4, ZTMP5, ZTMP6, ZTMP7, ZTMP8, ZTMP9, ZTMP10, ZTMP11, ZTMP12, ZTMP13, ZTMP14, ZTMP15, ZTMP16, ZTMP17, ZTMP18, ZTMP19, ZTMP20, ZTMP21, ZTMP22, GH, GL, GM, IA0, IA1, MASKREG, SHUFMASK, NROUNDS) \
        jmp     20f;        \
6:;     \
        INITIAL_BLOCKS_PARTIAL(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, LENGTH, DATA_OFFSET, 6, CTR, HASH_IN_OUT, ENC_DEC, INSTANCE_TYPE, ZTMP0, ZTMP1, ZTMP2, ZTMP3, ZTMP4, ZTMP5, ZTMP6, ZTMP7, ZTMP8, ZTMP9, ZTMP10, ZTMP11, ZTMP12, ZTMP13, ZTMP14, ZTMP15, ZTMP16, ZTMP17, ZTMP18, ZTMP19, ZTMP20, ZTMP21, ZTMP22, GH, GL, GM, IA0, IA1, MASKREG, SHUFMASK, NROUNDS) \
        jmp     20f;        \
7:;     \
        INITIAL_BLOCKS_PARTIAL(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, LENGTH, DATA_OFFSET, 7, CTR, HASH_IN_OUT, ENC_DEC, INSTANCE_TYPE, ZTMP0, ZTMP1, ZTMP2, ZTMP3, ZTMP4, ZTMP5, ZTMP6, ZTMP7, ZTMP8, ZTMP9, ZTMP10, ZTMP11, ZTMP12, ZTMP13, ZTMP14, ZTMP15, ZTMP16, ZTMP17, ZTMP18, ZTMP19, ZTMP20, ZTMP21, ZTMP22, GH, GL, GM, IA0, IA1, MASKREG, SHUFMASK, NROUNDS) \
        jmp     20f;        \
8:;     \
        INITIAL_BLOCKS_PARTIAL(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, LENGTH, DATA_OFFSET, 8, CTR, HASH_IN_OUT, ENC_DEC, INSTANCE_TYPE, ZTMP0, ZTMP1, ZTMP2, ZTMP3, ZTMP4, ZTMP5, ZTMP6, ZTMP7, ZTMP8, ZTMP9, ZTMP10, ZTMP11, ZTMP12, ZTMP13, ZTMP14, ZTMP15, ZTMP16, ZTMP17, ZTMP18, ZTMP19, ZTMP20, ZTMP21, ZTMP22, GH, GL, GM, IA0, IA1, MASKREG, SHUFMASK, NROUNDS) \
        jmp     20f;        \
9:;     \
        INITIAL_BLOCKS_PARTIAL(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, LENGTH, DATA_OFFSET, 9, CTR, HASH_IN_OUT, ENC_DEC, INSTANCE_TYPE, ZTMP0, ZTMP1, ZTMP2, ZTMP3, ZTMP4, ZTMP5, ZTMP6, ZTMP7, ZTMP8, ZTMP9, ZTMP10, ZTMP11, ZTMP12, ZTMP13, ZTMP14, ZTMP15, ZTMP16, ZTMP17, ZTMP18, ZTMP19, ZTMP20, ZTMP21, ZTMP22, GH, GL, GM, IA0, IA1, MASKREG, SHUFMASK, NROUNDS) \
        jmp     20f;        \
10:;    \
        INITIAL_BLOCKS_PARTIAL(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, LENGTH, DATA_OFFSET, 10, CTR, HASH_IN_OUT, ENC_DEC, INSTANCE_TYPE, ZTMP0, ZTMP1, ZTMP2, ZTMP3, ZTMP4, ZTMP5, ZTMP6, ZTMP7, ZTMP8, ZTMP9, ZTMP10, ZTMP11, ZTMP12, ZTMP13, ZTMP14, ZTMP15, ZTMP16, ZTMP17, ZTMP18, ZTMP19, ZTMP20, ZTMP21, ZTMP22, GH, GL, GM, IA0, IA1, MASKREG, SHUFMASK, NROUNDS) \
        jmp     20f;        \
11:;    \
        INITIAL_BLOCKS_PARTIAL(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, LENGTH, DATA_OFFSET, 11, CTR, HASH_IN_OUT, ENC_DEC, INSTANCE_TYPE, ZTMP0, ZTMP1, ZTMP2, ZTMP3, ZTMP4, ZTMP5, ZTMP6, ZTMP7, ZTMP8, ZTMP9, ZTMP10, ZTMP11, ZTMP12, ZTMP13, ZTMP14, ZTMP15, ZTMP16, ZTMP17, ZTMP18, ZTMP19, ZTMP20, ZTMP21, ZTMP22, GH, GL, GM, IA0, IA1, MASKREG, SHUFMASK, NROUNDS) \
        jmp     20f;        \
12:;    \
        INITIAL_BLOCKS_PARTIAL(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, LENGTH, DATA_OFFSET, 12, CTR, HASH_IN_OUT, ENC_DEC, INSTANCE_TYPE, ZTMP0, ZTMP1, ZTMP2, ZTMP3, ZTMP4, ZTMP5, ZTMP6, ZTMP7, ZTMP8, ZTMP9, ZTMP10, ZTMP11, ZTMP12, ZTMP13, ZTMP14, ZTMP15, ZTMP16, ZTMP17, ZTMP18, ZTMP19, ZTMP20, ZTMP21, ZTMP22, GH, GL, GM, IA0, IA1, MASKREG, SHUFMASK, NROUNDS) \
        jmp     20f;        \
13:;    \
        INITIAL_BLOCKS_PARTIAL(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, LENGTH, DATA_OFFSET, 13, CTR, HASH_IN_OUT, ENC_DEC, INSTANCE_TYPE, ZTMP0, ZTMP1, ZTMP2, ZTMP3, ZTMP4, ZTMP5, ZTMP6, ZTMP7, ZTMP8, ZTMP9, ZTMP10, ZTMP11, ZTMP12, ZTMP13, ZTMP14, ZTMP15, ZTMP16, ZTMP17, ZTMP18, ZTMP19, ZTMP20, ZTMP21, ZTMP22, GH, GL, GM, IA0, IA1, MASKREG, SHUFMASK, NROUNDS) \
        jmp     20f;        \
14:;    \
        INITIAL_BLOCKS_PARTIAL(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, LENGTH, DATA_OFFSET, 14, CTR, HASH_IN_OUT, ENC_DEC, INSTANCE_TYPE, ZTMP0, ZTMP1, ZTMP2, ZTMP3, ZTMP4, ZTMP5, ZTMP6, ZTMP7, ZTMP8, ZTMP9, ZTMP10, ZTMP11, ZTMP12, ZTMP13, ZTMP14, ZTMP15, ZTMP16, ZTMP17, ZTMP18, ZTMP19, ZTMP20, ZTMP21, ZTMP22, GH, GL, GM, IA0, IA1, MASKREG, SHUFMASK, NROUNDS) \
        jmp     20f;        \
15:;    \
        INITIAL_BLOCKS_PARTIAL(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, LENGTH, DATA_OFFSET, 15, CTR, HASH_IN_OUT, ENC_DEC, INSTANCE_TYPE, ZTMP0, ZTMP1, ZTMP2, ZTMP3, ZTMP4, ZTMP5, ZTMP6, ZTMP7, ZTMP8, ZTMP9, ZTMP10, ZTMP11, ZTMP12, ZTMP13, ZTMP14, ZTMP15, ZTMP16, ZTMP17, ZTMP18, ZTMP19, ZTMP20, ZTMP21, ZTMP22, GH, GL, GM, IA0, IA1, MASKREG, SHUFMASK, NROUNDS) \
        jmp     20f;        \
16:;    \
        INITIAL_BLOCKS_PARTIAL(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, LENGTH, DATA_OFFSET, 16, CTR, HASH_IN_OUT, ENC_DEC, INSTANCE_TYPE, ZTMP0, ZTMP1, ZTMP2, ZTMP3, ZTMP4, ZTMP5, ZTMP6, ZTMP7, ZTMP8, ZTMP9, ZTMP10, ZTMP11, ZTMP12, ZTMP13, ZTMP14, ZTMP15, ZTMP16, ZTMP17, ZTMP18, ZTMP19, ZTMP20, ZTMP21, ZTMP22, GH, GL, GM, IA0, IA1, MASKREG, SHUFMASK, NROUNDS) \
20:;       \

#define ZMM_LOAD_BLOCKS_0_16(NUM_BLOCKS, INP, DATA_OFFSET, DST0, DST1, DST2, DST3) \
.set src_offset, 0;	\
.set blocks_left, NUM_BLOCKS % 4;	\
.if NUM_BLOCKS < 4; \
	.if blocks_left == 1; \
        	vmovdqu8        src_offset(INP, DATA_OFFSET), XWORD(DST0); \
	.elseif blocks_left == 2; \
	        vmovdqu8        src_offset(INP, DATA_OFFSET), YWORD(DST0); \
	.elseif blocks_left == 3; \
        	vmovdqu8        src_offset(INP, DATA_OFFSET), YWORD(DST0); \
	        vinserti64x2    $2, src_offset + 32(INP, DATA_OFFSET), DST0, DST0; \
	.endif; \
.elseif NUM_BLOCKS >= 4 && NUM_BLOCKS < 8;	\
	vmovdqu8        src_offset(INP, DATA_OFFSET), DST0; \
	.set src_offset, src_offset + 64;     \
	.if blocks_left == 1; \
                vmovdqu8        src_offset(INP, DATA_OFFSET), XWORD(DST1); \
        .elseif blocks_left == 2; \
                vmovdqu8        src_offset(INP, DATA_OFFSET), YWORD(DST1); \
        .elseif blocks_left == 3; \
                vmovdqu8        src_offset(INP, DATA_OFFSET), YWORD(DST1); \
                vinserti64x2    $2, src_offset+32(INP, DATA_OFFSET), DST1, DST1; \
        .endif; \
.elseif NUM_BLOCKS >= 8 && NUM_BLOCKS < 12;      \
	vmovdqu8        src_offset(INP, DATA_OFFSET), DST0; \
        .set src_offset, src_offset + 64;     \
	vmovdqu8        src_offset(INP, DATA_OFFSET), DST1; \
        .set src_offset, src_offset + 64;     \
	.if blocks_left == 1; \
                vmovdqu8        src_offset(INP, DATA_OFFSET), XWORD(DST2); \
        .elseif blocks_left == 2; \
                vmovdqu8        src_offset(INP, DATA_OFFSET), YWORD(DST2); \
        .elseif blocks_left == 3; \
                vmovdqu8        src_offset(INP, DATA_OFFSET), YWORD(DST2); \
                vinserti64x2    $2, src_offset+32(INP, DATA_OFFSET), DST2, DST2; \
        .endif; \
.else;	\
	vmovdqu8        src_offset(INP, DATA_OFFSET), DST0; \
        .set src_offset, src_offset + 64;     \
        vmovdqu8        src_offset(INP, DATA_OFFSET), DST1; \
        .set src_offset, src_offset + 64;     \
	vmovdqu8        src_offset(INP, DATA_OFFSET), DST2; \
        .set src_offset, src_offset + 64;     \
	.if blocks_left == 1; \
                vmovdqu8        src_offset(INP, DATA_OFFSET), XWORD(DST3); \
        .elseif blocks_left == 2; \
                vmovdqu8        src_offset(INP, DATA_OFFSET), YWORD(DST3); \
        .elseif blocks_left == 3; \
                vmovdqu8        src_offset(INP, DATA_OFFSET), YWORD(DST3); \
                vinserti64x2    $2, src_offset+32(INP, DATA_OFFSET), DST3, DST3; \
        .endif; \
.endif;

#define ZMM_STORE_BLOCKS_0_16(NUM_BLOCKS, OUTP, DATA_OFFSET, SRC0, SRC1, SRC2, SRC3) \
.set dst_offset, 0;     \
.set blocks_left, NUM_BLOCKS % 4;       \
.if NUM_BLOCKS < 4; \
        .if blocks_left == 1; \
                vmovdqu8        XWORD(SRC0), dst_offset(OUTP, DATA_OFFSET); \
        .elseif blocks_left == 2; \
                vmovdqu8        YWORD(SRC0), dst_offset(OUTP, DATA_OFFSET); \
        .elseif blocks_left == 3; \
                vmovdqu8        YWORD(SRC0), dst_offset(OUTP, DATA_OFFSET); \
                vextracti32x4   $2, SRC0, dst_offset + 32(OUTP, DATA_OFFSET); \
        .endif; \
.elseif NUM_BLOCKS >= 4 && NUM_BLOCKS < 8;      \
        vmovdqu8        SRC0, dst_offset(OUTP, DATA_OFFSET); \
        .set dst_offset, dst_offset + 64;     \
        .if blocks_left == 1; \
                vmovdqu8        XWORD(SRC1), dst_offset(OUTP, DATA_OFFSET); \
        .elseif blocks_left == 2; \
                vmovdqu8        YWORD(SRC1), dst_offset(OUTP, DATA_OFFSET); \
        .elseif blocks_left == 3; \
                vmovdqu8        YWORD(SRC1), dst_offset(OUTP, DATA_OFFSET); \
                vextracti32x4   $2, SRC1, dst_offset + 32(OUTP, DATA_OFFSET); \
        .endif; \
.elseif NUM_BLOCKS >= 8 && NUM_BLOCKS < 12;      \
        vmovdqu8        SRC0, dst_offset(OUTP, DATA_OFFSET); \
        .set dst_offset, dst_offset + 64;     \
        vmovdqu8        SRC1, dst_offset(OUTP, DATA_OFFSET); \
        .set dst_offset, dst_offset + 64;     \
        .if blocks_left == 1; \
                vmovdqu8        XWORD(SRC2), dst_offset(OUTP, DATA_OFFSET); \
        .elseif blocks_left == 2; \
                vmovdqu8        YWORD(SRC2), dst_offset(OUTP, DATA_OFFSET); \
        .elseif blocks_left == 3; \
                vmovdqu8        YWORD(SRC2), dst_offset(OUTP, DATA_OFFSET); \
                vextracti32x4   $2, SRC2, dst_offset + 32(OUTP, DATA_OFFSET); \
        .endif; \
.else;  \
	vmovdqu8        SRC0, dst_offset(OUTP, DATA_OFFSET); \
        .set dst_offset, dst_offset + 64;     \
        vmovdqu8        SRC1, dst_offset(OUTP, DATA_OFFSET); \
        .set dst_offset, dst_offset + 64;     \
	vmovdqu8        SRC2, dst_offset(OUTP, DATA_OFFSET); \
        .set dst_offset, dst_offset + 64;     \
	.if blocks_left == 1; \
                vmovdqu8        XWORD(SRC3), dst_offset(OUTP, DATA_OFFSET); \
        .elseif blocks_left == 2; \
                vmovdqu8        YWORD(SRC3), dst_offset(OUTP, DATA_OFFSET); \
        .elseif blocks_left == 3; \
                vmovdqu8        YWORD(SRC3), dst_offset(OUTP, DATA_OFFSET); \
                vinserti64x2    $2, SRC3, dst_offset + 32(OUTP, DATA_OFFSET), dst_offset + 32(OUTP, DATA_OFFSET); \
        .endif; \
.endif;	\

#define INITIAL_BLOCKS(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, LENGTH, DATA_OFFSET, num_initial_blocks, CTR, AAD_HASH, ZT1, ZT2, ZT3, ZT4, ZT5, ZT6, ZT7, ZT8, ZT9, ZT10, ZT11, ZT12, IA0, IA1, END_DEC, MASKREG, SHUFMASK, PARTIAL_PRESENT, NROUNDS) \
.set partial_block_possible, 1;	\
.ifc PARTIAL_PRESENT, no_partial_block;	\
	.set partial_block_possible, 0; \
.endif;	\
.if num_initial_blocks > 0; \
    .if num_initial_blocks == 1; \
        vpaddd          ONE(%rip), CTR, XWORD(ZT3); \
    .elseif num_initial_blocks == 2; \
        vshufi64x2      $0, YWORD(CTR), YWORD(CTR), YWORD(ZT3); \
        vpaddd          ddq_add_1234(%rip), YWORD(ZT3), YWORD(ZT3); \
    .else; \
        vshufi64x2      $0, ZWORD(CTR), ZWORD(CTR), ZWORD(CTR); \
        vpaddd          ddq_add_1234(%rip), ZWORD(CTR), ZT3; \
        vpaddd          ddq_add_5678(%rip), ZWORD(CTR), ZT4; \
    .endif; \
\
    .if num_initial_blocks <= 4; \
            vextracti32x4   $(num_initial_blocks - 1), ZT3, CTR; \
    .else; \
            vextracti32x4   $(num_initial_blocks - 5), ZT4, CTR; \
    .endif; \
    ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16(num_initial_blocks, vpshufb, ZT3, ZT4, no_zmm, no_zmm, ZT3, ZT4, no_zmm, no_zmm, SHUFMASK, SHUFMASK, SHUFMASK, SHUFMASK) \
    ZMM_LOAD_BLOCKS_0_16(num_initial_blocks, PLAIN_CYPH_IN, DATA_OFFSET, ZT5, ZT6, no_zmm, no_zmm) \
.if NROUNDS==9;	\
    vbroadcastf64x2 (GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 0, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 16(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 1, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 32(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 2, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 48(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 3, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 64(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 4, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 80(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 5, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 96(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 6, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 112(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 7, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 128(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 8, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 144(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 9, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 160(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 10, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
.elseif NROUNDS==11;	\
    vbroadcastf64x2 (GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 0, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 16(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 1, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 32(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 2, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 48(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 3, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 64(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 4, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 80(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 5, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 96(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 6, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 112(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 7, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 128(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 8, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 144(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 9, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 160(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 10, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 176(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 11, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 192(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 12, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
.elseif NROUNDS==13;	\
    vbroadcastf64x2 (GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 0, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 16(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 1, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 32(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 2, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 48(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 3, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 64(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 4, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 80(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 5, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 96(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 6, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 112(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 7, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 128(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 8, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 144(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 9, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 160(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 10, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 176(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 11, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 192(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 12, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 208(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 13, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
    vbroadcastf64x2 224(GDATA_KEY), ZT1; \
    ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT1, 14, ZT5, ZT6, no_zmm, no_zmm, num_initial_blocks, NROUNDS) \
.endif;	\
    ZMM_STORE_BLOCKS_0_16(num_initial_blocks, CYPH_PLAIN_OUT, DATA_OFFSET, ZT3, ZT4, no_zmm, no_zmm) \
    .ifc ENC_DEC, DEC; \
    ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16(num_initial_blocks, vpshufb, ZT5, ZT6, no_zmm, no_zmm, ZT5, ZT6, no_zmm, no_zmm, SHUFMASK, SHUFMASK, SHUFMASK, SHUFMASK) \
    .else; \
    ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16(num_initial_blocks, vpshufb, ZT5, ZT6, no_zmm, no_zmm, ZT3, ZT4, no_zmm, no_zmm, SHUFMASK, SHUFMASK, SHUFMASK, SHUFMASK) \
    .endif; \
        sub             $(num_initial_blocks * 16), LENGTH; \
        add             $(num_initial_blocks * 16), DATA_OFFSET; \
.endif;	\
    vshufi64x2		$0, ZWORD(CTR), ZWORD(CTR), ZWORD(CTR);	\
    vpaddd          ddq_add_1234(%rip), ZWORD(CTR), ZT3; \
    vpaddd          ddq_add_5678(%rip), ZWORD(CTR), ZT4; \
    vextracti32x4	$3, ZT4, CTR;	\
    vpshufb		SHUFMASK, ZT3, ZT3;	\
    vpshufb             SHUFMASK, ZT4, ZT4;  \
.if partial_block_possible != 0;        \
        mov     0xffffffffffffffff, IA0;     \
        .if num_initial_blocks > 0;     \
                cmp     $128, LENGTH;   \
                jge     _initial_partial_block_continue;        \
                mov     %rcx, IA1;      \
                mov     $128, %rcx;     \
                sub     LENGTH, %rcx;   \
                shr     cl, IA0;        \
                mov     IA1, %rcx;      \
_initial_partial_block_continue:;       \
        .endif; \
        kmovq   IA0, MASKREG;   \
        ZMM_LOAD_MASKED_BLOCKS_0_16(8, PLAIN_CYPH_IN, DATA_OFFSET, ZT1, ZT2, no_zmm, no_zmm, MASKREG)   \
.else;  \
        ZMM_LOAD_BLOCKS_0_16(8, PLAIN_CYPH_IN, DATA_OFFSET, ZT1, ZT2, no_zmm, no_zmm)   \
.endif; \
.set aes_round, 0;      \
        vbroadcastf64x2 (aes_round * 16)(GDATA_KEY), ZT8;       \
        ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT8, aes_round, ZT1, ZT2, no_zmm, no_zmm, 8, NROUNDS)    \
.set aes_round, aes_round + 1;  \
.if num_initial_blocks > 0;     \
        vpxorq  AAD_HASH, ZT5, ZT5;     \
        VCLMUL_1_TO_8_STEP1(GDATA_KEY, ZT6, ZT8, ZT9, ZT10, ZT11, ZT12, num_initial_blocks);  \
.endif; \
.rept ((NROUNDS + 1) / 3);      \
        vbroadcastf64x2 (aes_round * 16)(GDATA_KEY), ZT8;       \
        ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT8, aes_round, ZT1, ZT2, no_zmm, no_zmm, 8, NROUNDS)    \
.set aes_round, aes_round + 1;  \
.endr;  \
.if num_initial_blocks > 0;     \
        VCLMUL_1_TO_8_STEP2(GDATA_KEY, ZT6, ZT5, ZT7, ZT8, ZT9, ZT10, ZT11, ZT12, num_initial_blocks);        \
.endif; \
.rept ((NROUNDS + 1) / 3);      \
        vbroadcastf64x2         (aes_round * 16)(GDATA_KEY), ZT8;       \
        ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT8, aes_round, ZT1, ZT2, no_zmm, no_zmm, 8, NROUNDS);   \
        .set aes_round, aes_round + 1;  \
.endr;  \
.if num_initial_blocks > 0;     \
        vmovdqu64       POLY2(%rip), XWORD(ZT8); \
	VCLMUL_REDUCE(XWORD(AAD_HASH), XWORD(ZT8), XWORD(ZT6), XWORD(ZT5), XWORD(ZT7), XWORD(ZT9))      \
.endif; \
.rept (((NROUNDS + 1) / 3) + 2);        \
.if aes_round < (NROUNDS + 2);  \
        vbroadcastf64x2         (aes_round * 16)(GDATA_KEY), ZT8;       \
        ZMM_AESENC_ROUND_BLOCKS_0_16(ZT3, ZT4, no_zmm, no_zmm, ZT8, aes_round, ZT1, ZT2, no_zmm, no_zmm, 8, NROUNDS)    \
.set aes_round, aes_round + 1;  \
.endif; \
.endr;  \
.if partial_block_possible != 0;        \
        ZMM_STORE_MASKED_BLOCKS_0_16(8, CYPH_PLAIN_OUT, DATA_OFFSET, ZT3, ZT4, no_zmm, no_zmm, MASKREG) \
        cmp             $128, LENGTH;   \
        jl              2f;  \
        add             $128, DATA_OFFSET;      \
        sub             $128, LENGTH;   \
        jmp             1f;   \
2:; \
        vextracti32x4   $3, ZT4, PBlockEncKey(GDATA_CTX);       \
        add             LENGTH, DATA_OFFSET;    \
        sub             $(128 - 16), LENGTH;    \
        mov             LENGTH, PBlockLen(GDATA_CTX);   \
        xor             LENGTH, LENGTH; \
        vmovdqu8        ZT4, ZT4{MASKREG}{z};   \
1:;	\
.else;  \
        ZMM_STORE_BLOCKS_0_16(8, CYPH_PLAIN_OUT, DATA_OFFSET, ZT3, ZT4, no_zmm, no_zmm) \
        add             $128, DATA_OFFSET;	\
        sub             $128, LENGTH;	\
.endif;	\
.ifc  ENC_DEC, DEC;     \
        vpshufb         SHUFMASK, ZT1;  \
        vpshufb         SHUFMASK, ZT2;  \
.else;  \
        vpshufb         SHUFMASK, ZT3, ZT1;     \
        vpshufb         SHUFMASK, ZT4, ZT2;     \
.endif; \
        vpxorq          AAD_HASH, ZT1, ZT1;     \

#define GHASH_8_ENCRYPT_8_PARALLEL(GDATA, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, DATA_OFFSET, CTR1, CTR2, GHASHIN_AESOUT_B03, GHASHIN_AESOUT_B47, AES_PARTIAL_BLOCK, loop_idx, ENC_DEC, FULL_PARTIAL, IA0, IA1, LENGTH, INSTANCE_TYPE, GH4KEY, GH8KEY, SHFMSK, ZT1, ZT2, ZT3, ZT4, ZT5, ZT10, ZT11, ZT12, ZT13, ZT14, ZT15, ZT16, ZT17, MASKREG, DO_REDUCTION, TO_REDUCE_L, TO_REDUCE_H, TO_REDUCE_M, NROUNDS) \
.ifc loop_idx, in_order; \
        vpshufb         SHFMSK, CTR1, ZT1; \
        vpshufb         SHFMSK, CTR2, ZT2; \
.else; \
        vmovdqa64       CTR1, ZT1; \
        vmovdqa64       CTR2, ZT2; \
.endif; \
        vbroadcastf64x2 16*0(GDATA), ZT3; \
        ZMM_AESENC_ROUND_BLOCKS_0_16(ZT1, ZT2, no_zmm, no_zmm, ZT3, 0, ZT4, ZT5, no_zmm, no_zmm, 8, NROUNDS) \
        vpclmulqdq      $0x11, GH4KEY, GHASHIN_AESOUT_B47, ZT10; \
        vpclmulqdq      $0x00, GH4KEY, GHASHIN_AESOUT_B47, ZT11; \
        vpclmulqdq      $0x01, GH4KEY, GHASHIN_AESOUT_B47, ZT12; \
        vpclmulqdq      $0x10, GH4KEY, GHASHIN_AESOUT_B47, ZT13; \
        vbroadcastf64x2 16*1(GDATA), ZT3; \
        ZMM_AESENC_ROUND_BLOCKS_0_16(ZT1, ZT2, no_zmm, no_zmm, ZT3, 1, ZT4, ZT5, no_zmm, no_zmm, 8, NROUNDS) \
        vbroadcastf64x2 16*2(GDATA), ZT3; \
        ZMM_AESENC_ROUND_BLOCKS_0_16(ZT1, ZT2, no_zmm, no_zmm, ZT3, 2, ZT4, ZT5, no_zmm, no_zmm, 8, NROUNDS) \
        vbroadcastf64x2 16*3(GDATA), ZT3; \
        ZMM_AESENC_ROUND_BLOCKS_0_16(ZT1, ZT2, no_zmm, no_zmm, ZT3, 3, ZT4, ZT5, no_zmm, no_zmm, 8, NROUNDS) \
        vpclmulqdq      $0x10, GH8KEY, GHASHIN_AESOUT_B03, ZT16; \
        vpclmulqdq      $0x01, GH8KEY, GHASHIN_AESOUT_B03, ZT17; \
        vpclmulqdq      $0x11, GH8KEY, GHASHIN_AESOUT_B03, ZT14; \
        vpclmulqdq      $0x00, GH8KEY, GHASHIN_AESOUT_B03, ZT15; \
        vbroadcastf64x2 16*4(GDATA), ZT3; \
        ZMM_AESENC_ROUND_BLOCKS_0_16(ZT1, ZT2, no_zmm, no_zmm, ZT3, 4, ZT4, ZT5, no_zmm, no_zmm, 8, NROUNDS) \
	vbroadcastf64x2 16*5(GDATA), ZT3; \
        ZMM_AESENC_ROUND_BLOCKS_0_16(ZT1, ZT2, no_zmm, no_zmm, ZT3, 5, ZT4, ZT5, no_zmm, no_zmm, 8, NROUNDS) \
	vbroadcastf64x2 16*6(GDATA), ZT3; \
        ZMM_AESENC_ROUND_BLOCKS_0_16(ZT1, ZT2, no_zmm, no_zmm, ZT3, 6, ZT4, ZT5, no_zmm, no_zmm, 8, NROUNDS) \
.ifc DO_REDUCTION, no_reduction; \
        vpternlogq      $0x96, ZT16, ZT13, ZT12; \
        vpternlogq      $0x96, ZT17, ZT12, TO_REDUCE_M; \
        vpternlogq      $0x96, ZT14, ZT10, TO_REDUCE_H; \
        vpternlogq      $0x96, ZT15, ZT11, TO_REDUCE_L; \
.endif; \
.ifc DO_REDUCTION, do_reduction; \
        vpternlogq      $0x96, ZT16, ZT13, ZT12; \
        vpxorq          ZT17, ZT12, ZT12; \
        vpsrldq         $8, ZT12, ZT16; \
        vpslldq         $8, ZT12, ZT12; \
.endif; \
.ifc DO_REDUCTION, final_reduction; \
        vpternlogq      $0x96, ZT16, ZT13, ZT12; \
        vpternlogq      $0x96, ZT17, TO_REDUCE_M, ZT12; \
        vpsrldq         $8, ZT12, ZT16; \
        vpslldq         $8, ZT12, ZT12; \
.endif; \
        vbroadcastf64x2 16*7(GDATA), ZT3; \
        ZMM_AESENC_ROUND_BLOCKS_0_16(ZT1, ZT2, no_zmm, no_zmm, ZT3, 7, ZT4, ZT5, no_zmm, no_zmm, 8, NROUNDS) \
        vbroadcastf64x2 16*8(GDATA), ZT3; \
        ZMM_AESENC_ROUND_BLOCKS_0_16(ZT1, ZT2, no_zmm, no_zmm, ZT3, 8, ZT4, ZT5, no_zmm, no_zmm, 8, NROUNDS) \
.ifc DO_REDUCTION, final_reduction; \
        vpternlogq      $0x96, ZT16, ZT14, ZT10; \
        vpxorq          TO_REDUCE_H, ZT10; \
        vpternlogq      $0x96, ZT12, ZT15, ZT11; \
        vpxorq          TO_REDUCE_L, ZT11; \
.endif; \
.ifc DO_REDUCTION, do_reduction; \
        vpternlogq      $0x96, ZT16, ZT14, ZT10; \
        vpternlogq      $0x96, ZT12, ZT15, ZT11; \
.endif; \
.ifnc DO_REDUCTION, no_reduction; \
        VHPXORI4x128    ZT14, ZT10; \
        VHPXORI4x128    ZT15, ZT11; \
.endif; \
.if 9 < (NROUNDS + 1); \
.if NROUNDS==9;	\
        vbroadcastf64x2 16*9(GDATA), ZT3; \
        ZMM_AESENC_ROUND_BLOCKS_0_16(ZT1, ZT2, no_zmm, no_zmm, ZT3, 9, ZT4, ZT5, no_zmm, no_zmm, 8, NROUNDS) \
.else;	\
	vbroadcastf64x2 16*9(GDATA), ZT3; \
        ZMM_AESENC_ROUND_BLOCKS_0_16(ZT1, ZT2, no_zmm, no_zmm, ZT3, 9, ZT4, ZT5, no_zmm, no_zmm, 8, NROUNDS) \
	vbroadcastf64x2 16*10(GDATA), ZT3; \
        ZMM_AESENC_ROUND_BLOCKS_0_16(ZT1, ZT2, no_zmm, no_zmm, ZT3, 10, ZT4, ZT5, no_zmm, no_zmm, 8, NROUNDS) \
.endif;	\
.endif; \
.ifnc DO_REDUCTION, no_reduction; \
        vmovdqu64       POLY2(%rip), XWORD(ZT17); \
        vpclmulqdq      $0x01, XWORD(ZT11), XWORD(ZT17), XWORD(ZT15); \
        vpslldq         $8, XWORD(ZT15), XWORD(ZT15); \
        vpxorq          XWORD(ZT15), XWORD(ZT11), XWORD(ZT15); \
.endif; \
.if 11 < (NROUNDS + 1); \
.if NROUNDS==11; \
        vbroadcastf64x2 16*11(GDATA), ZT3; \
        ZMM_AESENC_ROUND_BLOCKS_0_16(ZT1, ZT2, no_zmm, no_zmm, ZT3, 11, ZT4, ZT5, no_zmm, no_zmm, 8, NROUNDS) \
.else;  \
        vbroadcastf64x2 16*11(GDATA), ZT3; \
        ZMM_AESENC_ROUND_BLOCKS_0_16(ZT1, ZT2, no_zmm, no_zmm, ZT3, 11, ZT4, ZT5, no_zmm, no_zmm, 8, NROUNDS) \
        vbroadcastf64x2 16*12(GDATA), ZT3; \
        ZMM_AESENC_ROUND_BLOCKS_0_16(ZT1, ZT2, no_zmm, no_zmm, ZT3, 12, ZT4, ZT5, no_zmm, no_zmm, 8, NROUNDS) \
.endif;	\
.endif;	\
.ifnc DO_REDUCTION, no_reduction; \
        vpclmulqdq      $0x00, XWORD(ZT15), XWORD(ZT17), XWORD(ZT16); \
        vpsrldq         $4, XWORD(ZT16), XWORD(ZT16); \
        vpclmulqdq      $0x10, XWORD(ZT15), XWORD(ZT17), XWORD(ZT13); \
        vpslldq         $4, XWORD(ZT13), XWORD(ZT13); \
        vpternlogq      $0x96, XWORD(ZT10), XWORD(ZT16), XWORD(ZT13); \
.endif; \
.if 13 < (NROUNDS + 1); \
	vbroadcastf64x2 16*13(GDATA), ZT3; \
        ZMM_AESENC_ROUND_BLOCKS_0_16(ZT1, ZT2, no_zmm, no_zmm, ZT3, 13, ZT4, ZT5, no_zmm, no_zmm, 8, NROUNDS) \
.endif;	\
.ifc FULL_PARTIAL, full; \
        vmovdqu8        (PLAIN_CYPH_IN, DATA_OFFSET), ZT4; \
        vmovdqu8        64(PLAIN_CYPH_IN, DATA_OFFSET), ZT5; \
.else; \
        lea             byte64_len_to_mask_table(%rip), IA0; \
        mov             LENGTH, IA1; \
        sub             $64, IA1; \
        kmovq           (IA0, IA1, 8), MASKREG; \
        vmovdqu8        (PLAIN_CYPH_IN, DATA_OFFSET), ZT4; \
        vmovdqu8        64(PLAIN_CYPH_IN, DATA_OFFSET), ZT5{MASKREG}{z}; \
.endif; \
.if NROUNDS == 9; \
        vbroadcastf64x2 16*10(GDATA), ZT3; \
        ZMM_AESENC_ROUND_BLOCKS_0_16(ZT1, ZT2, no_zmm, no_zmm, ZT3, 10, ZT4, ZT5, no_zmm, no_zmm, 8, NROUNDS) \
.elseif NROUNDS == 11;	\
	vbroadcastf64x2 16*12(GDATA), ZT3; \
        ZMM_AESENC_ROUND_BLOCKS_0_16(ZT1, ZT2, no_zmm, no_zmm, ZT3, 12, ZT4, ZT5, no_zmm, no_zmm, 8, NROUNDS) \
.elseif NROUNDS == 13;  \
        vbroadcastf64x2 16*14(GDATA), ZT3; \
        ZMM_AESENC_ROUND_BLOCKS_0_16(ZT1, ZT2, no_zmm, no_zmm, ZT3, 14, ZT4, ZT5, no_zmm, no_zmm, 8, NROUNDS) \
.endif;	\
.ifc FULL_PARTIAL, full; \
        vmovdqu8        ZT1, (CYPH_PLAIN_OUT, DATA_OFFSET); \
        vmovdqu8        ZT2, 64(CYPH_PLAIN_OUT, DATA_OFFSET); \
.else; \
        vmovdqu8        ZT1, (CYPH_PLAIN_OUT, DATA_OFFSET); \
        vmovdqu8        ZT2, 64(CYPH_PLAIN_OUT, DATA_OFFSET){MASKREG}; \
.endif; \
.ifnc FULL_PARTIAL, full; \
.ifc INSTANCE_TYPE, multi_call; \
        vpxorq          ZT5, ZT2, ZT3; \
        vextracti32x4   $3, ZT3, AES_PARTIAL_BLOCK; \
.endif; \
.ifc ENC_DEC, ENC; \
        vmovdqu8        ZT2, ZT2{MASKREG}{z}; \
.else; \
        vmovdqu8        ZT5, ZT5{MASKREG}{z}; \
.endif; \
.endif; \
.ifc ENC_DEC, ENC; \
        vpshufb         SHFMSK, ZT1, GHASHIN_AESOUT_B03; \
        vpshufb         SHFMSK, ZT2, GHASHIN_AESOUT_B47; \
.else; \
        vpshufb         SHFMSK, ZT4, GHASHIN_AESOUT_B03; \
        vpshufb         SHFMSK, ZT5, GHASHIN_AESOUT_B47; \
.endif; \
.ifc DO_REDUCTION, do_reduction; \
        vpxorq          ZT13, GHASHIN_AESOUT_B03; \
.endif; \
.ifc DO_REDUCTION, final_reduction; \
        vmovdqa64       ZT13, TO_REDUCE_L; \
.endif;

#define GHASH_LAST_7(GDATA, BL47, BL03, ZTH, ZTM, ZTL, ZT01, ZT02, ZT03, ZT04, AAD_HASH, MASKREG, IA0, GH, GL,GM)       \
        vmovdqa64       POLY(%rip), XWORD(ZT04);        \
        VCLMUL_1_TO_8_STEP1(GDATA, BL47, ZT01, ZT02, ZTH, ZTM, ZTL, 7)  \
        vpxorq          GH, ZTH, ZTH;   \
        vpxorq          GL, ZTL, ZTL;   \
        vpxorq          GM, ZTM, ZTM;   \
        VCLMUL_1_TO_8_STEP2(GDATA, BL47, BL03, ZT01, ZT02, ZT03, ZTH, ZTM, ZTL, 7)      \
        VCLMUL_REDUCE(AAD_HASH, XWORD(ZT04), XWORD(BL47), XWORD(BL03), XWORD(ZT01), XWORD(ZT02))        \

#define GHASH_LAST_8(GDATA, BL47, BL03, ZTH, ZTM, ZTL, ZT01, ZT02, ZT03, AAD_HASH, GH, GL,GM)       \
	VCLMUL_STEP1_6(GDATA, BL47, ZT01, ZTH, ZTM, ZTL)	\
        vpxorq          GH, ZTH, ZTH;   \
        vpxorq          GL, ZTL, ZTL;   \
        vpxorq          GM, ZTM, ZTM;   \
	VCLMUL_STEP2_9(GDATA, BL47, BL03, ZT01, ZT02, ZT03, ZTH, ZTM, ZTL)	\
        vmovdqa64       POLY2(%rip), XWORD(ZT03);        \
	VCLMUL_REDUCE(AAD_HASH, XWORD(ZT03), XWORD(BL47), XWORD(BL03), XWORD(ZT01), XWORD(ZT02))        \

#define GCM_ENC_DEC(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, PLAIN_CYPH_LEN, ENC_DEC, INSTANCE_TYPE, NROUNDS)        \
        or              PLAIN_CYPH_LEN, PLAIN_CYPH_LEN; \
        je              21f;                  \
        xor             %r11, %r11;       \
        add             PLAIN_CYPH_LEN, InLen(GDATA_CTX);       \
        vmovdqu64       AadHash(GDATA_CTX), %xmm14;          \
        .ifc INSTANCE_TYPE, multi_call;                 \
        PARTIAL_BLOCK(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, PLAIN_CYPH_LEN, %r11, %xmm14, ENC_DEC, %r10, %r12, %r13, %zmm0, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm10, %zmm11, %zmm12, %zmm13, %k1)       \
       .endif;                                         \
	.ifc INSTANCE_TYPE, single_call;                \
        vmovdqu64       %xmm2, %xmm9;               \
        .else;  \
        vmovdqu64       CurCount(GDATA_CTX), %xmm9;        \
        .endif; \
	mov     PLAIN_CYPH_LEN, %r13;         \
        .ifc INSTANCE_TYPE, multi_call;         \
        sub     %r11, %r13;            \
        je      21f;                  \
        .endif; \
	vmovdqa64       SHUF_MASK(%rip), %zmm29;    \
        vmovdqa64       ddq_addbe_4444(%rip), %zmm27;        \
        cmp             $(big_loop_nblocks * 16), %r13;      \
	jl              12f;        \
	vmovdqa64	ddq_addbe_1234(%rip), %zmm28;		\
	INITIAL_BLOCKS_Nx16(%rcx, %rdx, %rdi, %r11, %zmm14, %zmm9, %r15, %zmm0, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm10, %zmm11, %zmm12, %zmm13, %zmm15, %zmm16, %zmm17, %zmm19, %zmm20, %zmm21, %zmm30, %zmm31, %zmm1, %zmm2, %zmm8, %zmm22, %zmm23, %zmm24 , %zmm25, %zmm26, %zmm27, %zmm28, %zmm29, ENC_DEC, 48, 32, NROUNDS)    \
	sub             $(big_loop_nblocks * 16), %r13;    \
        cmp             $(big_loop_nblocks * 16), %r13;    \
	jl              11f;      \
10:;     \
	GHASH_ENCRYPT_Nx16_PARALLEL(%rcx, %rdx, %rdi, %r11, %zmm9, %zmm29, %zmm0, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm10, %zmm11, %zmm12, %zmm13, %zmm15, %zmm16, %zmm17, %zmm19, %zmm20, %zmm21, %zmm30, %zmm31, %zmm1, %zmm2, %zmm8, %zmm22, %zmm23, %zmm24, %zmm25, %zmm26, %zmm27, %zmm28, %zmm14, ENC_DEC, 48, 32, %r15, NROUNDS)       \
	sub             $(big_loop_nblocks * 16), %r13;    \
        cmp             $(big_loop_nblocks * 16), %r13;    \
	jge             10b;      \
11:;     \
	vpshufb         %xmm29, %xmm9, %xmm9; \
        vmovdqa64       %xmm9, XWORD(%zmm28);           \
	GHASH_LAST_Nx16(GDATA_KEY, %zmm14, %zmm0, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm10, %zmm11, %zmm12, %zmm13, %zmm15, %zmm16, %zmm17, %zmm19, %zmm20, %zmm21, %zmm24, %zmm25, %zmm26, 48, 32)   \
	or              %r13, %r13;     \
	jz              20f;    \
12:;       \
	cmp             $256, %r13;     \
	jge		13f;	\
	mov             %r13, %r12;     \
        add             $15, %r12;      \
        shr             $4, %r12;       \
	GCM_ENC_DEC_SMALL(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, PLAIN_CYPH_LEN, ENC_DEC, %r11, %r13, %r12, %xmm9, %xmm14, INSTANCE_TYPE, %zmm0, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm10, %zmm11, %zmm12, %zmm13, %zmm15, %zmm16, %zmm17, %zmm19, %zmm20, %zmm21, %zmm30, %zmm31, %zmm1, %zmm2, %zmm8, %zmm22, %zmm23, no_zmm, no_zmm, no_zmm, %r10, %r15, %k1, %zmm29, NROUNDS)     \
	vmovdqa64       %xmm9, %xmm28;	\
	jmp     20f;     \
13:;   \
        mov             %r13, %r12;     \
        and             $0xff, %r12;    \
        add             $15, %r12;      \
        shr             $4, %r12;       \
        and             $7, %r12;       \
        je              8f;       \
        cmp             $1, %r12;       \
        je              1f;       \
        cmp             $2, %r12;       \
        je              2f;       \
        cmp             $3, %r12;       \
        je              3f;       \
        cmp             $4, %r12; \
        je              4f;       \
        cmp             $5, %r12; \
        je              5f;       \
        cmp             $6, %r12; \
        je              6f;       \
7:;      \
        INITIAL_BLOCKS(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, %r13, %r11, 7, %xmm9, %zmm14, %zmm0, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm10, %zmm11, %zmm12, %zmm13, %zmm15, %zmm16, %r10, %r12, ENC_DEC, %k1, %zmm29, no_partial_block, NROUNDS)     \
        jmp     9f;      \
6:;      \
        INITIAL_BLOCKS(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, %r13, %r11, 6, %xmm9, %zmm14, %zmm0, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm10, %zmm11, %zmm12, %zmm13, %zmm15, %zmm16, %r10, %r12, ENC_DEC, %k1, %zmm29, no_partial_block, NROUNDS)     \
        jmp     9f;      \
5:;      \
        INITIAL_BLOCKS(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, %r13, %r11, 5, %xmm9, %zmm14, %zmm0, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm10, %zmm11, %zmm12, %zmm13, %zmm15, %zmm16, %r10, %r12, ENC_DEC, %k1, %zmm29, no_partial_block, NROUNDS)     \
        jmp     9f;      \
4:;      \
        INITIAL_BLOCKS(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, %r13, %r11, 4, %xmm9, %zmm14, %zmm0, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm10, %zmm11, %zmm12, %zmm13, %zmm15, %zmm16, %r10, %r12, ENC_DEC, %k1, %zmm29, no_partial_block, NROUNDS)     \
        jmp     9f;      \
3:;      \
        INITIAL_BLOCKS(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, %r13, %r11, 3, %xmm9, %zmm14, %zmm0, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm10, %zmm11, %zmm12, %zmm13, %zmm15, %zmm16, %r10, %r12, ENC_DEC, %k1, %zmm29, no_partial_block, NROUNDS)     \
        jmp     9f;      \
2:;      \
        INITIAL_BLOCKS(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, %r13, %r11, 2, %xmm9, %zmm14, %zmm0, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm10, %zmm11, %zmm12, %zmm13, %zmm15, %zmm16, %r10, %r12, ENC_DEC, %k1, %zmm29, no_partial_block, NROUNDS)     \
        jmp     9f;      \
1:;      \
        INITIAL_BLOCKS(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, %r13, %r11, 1, %xmm9, %zmm14, %zmm0, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm10, %zmm11, %zmm12, %zmm13, %zmm15, %zmm16, %r10, %r12, ENC_DEC, %k1, %zmm29, no_partial_block, NROUNDS)     \
        jmp     9f;      \
8:;      \
        INITIAL_BLOCKS(GDATA_KEY, GDATA_CTX, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, %r13, %r11, 0, %xmm9, %zmm14, %zmm0, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm10, %zmm11, %zmm12, %zmm13, %zmm15, %zmm16, %r10, %r12, ENC_DEC, %k1, %zmm29, no_partial_block, NROUNDS)     \
9:;     \
        vmovdqa64       %xmm9, XWORD(%zmm28);    \
        vmovdqa64       %zmm0, %zmm1;   \
        vmovdqa64       %zmm3, %zmm2;   \
        lea             128(%r13), %r12;        \
        add             $15, %r12;      \
        and             $0x3f0, %r12;      \
        .ifc INSTANCE_TYPE, multi_call; \
        mov             %r13, %r10;     \
        and             $15, %r10;    \
        add             $15, %r10;      \
        and             $16, %r10;       \
        sub             %r10, %r12;       \
        .endif; \
	lea             (HashKey + 16)(GDATA_KEY), %rax;  \
        sub             %r12, %rax;     \
        vmovdqa64       ddq_addbe_8888(%rip), %zmm27;   \
        vmovdqa64       ddq_add_8888(%rip), %zmm19;     \
        vpxorq          %zmm24, %zmm24, %zmm24; \
        vpxorq          %zmm25, %zmm25, %zmm25; \
        vpxorq          %zmm26, %zmm26, %zmm26; \
        vshufi64x2      $0, %zmm9, %zmm9, %zmm9;        \
        vpaddd          ddq_add_5678(%rip), %zmm9, %zmm18;      \
        vpaddd          ddq_add_1234(%rip), %zmm9, %zmm9;       \
        vpshufb         %zmm29, %zmm9, %zmm9;        \
        vpshufb         %zmm29, %zmm18, %zmm18;      \
        cmp             $128, %r13;     \
        jl              17f;  \
14:; \
        vmovq           XWORD(%zmm28), %r15;    \
15:;     \
        and             $255, WORD(%r15);       \
        add             $8, WORD(%r15);         \
        vmovdqu64       64(%rax), %zmm31;       \
        vmovdqu64       (%rax), %zmm30;         \
	GHASH_8_ENCRYPT_8_PARALLEL(GDATA_KEY, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, %r11, %zmm9, %zmm18, %zmm1, %zmm2, %xmm8, out_order, ENC_DEC, full, %r10, %r12, %r13, INSTANCE_TYPE, %zmm31, %zmm30, %zmm29, %zmm0, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm10, %zmm11, %zmm12, %zmm13, %zmm15, %zmm16, %zmm17, %k1, no_reduction, %zmm25, %zmm24, %zmm26, NROUNDS)      \
	add             $128, %rax;             \
        add             $128, %r11;             \
        sub             $128, %r13;             \
        jz              18f;          \
        cmp             $248, WORD(%r15);       \
        jae             16f;          \
        vpaddd          %zmm27, %zmm9, %zmm9;           \
        vpaddd          %zmm27, %zmm18, %zmm18;          \
        cmp             $128, %r13;             \
        jl              17f;  \
        jmp             15b;      \
16:; \
        vpshufb         %zmm29, %zmm9, %zmm9;   \
        vpshufb         %zmm29, %zmm18, %zmm18; \
        vpaddd          %zmm19, %zmm9, %zmm9;  \
        vpaddd          %zmm19, %zmm18, %zmm18;  \
        vpshufb         %zmm29, %zmm9, %zmm9;  \
        vpshufb         %zmm29, %zmm18, %zmm18; \
        cmp             $128, %r13;     \
        jge             15b;      \
17:; \
        vmovdqu64       64(%rax), %zmm31;       \
        vmovdqu64       (%rax), %zmm30;         \
        GHASH_8_ENCRYPT_8_PARALLEL(GDATA_KEY, CYPH_PLAIN_OUT, PLAIN_CYPH_IN, %r11, %zmm9, %zmm18, %zmm1, %zmm2, %xmm8, out_order, ENC_DEC, partial, %r10, %r12, %r13, INSTANCE_TYPE, %zmm31, %zmm30, %zmm29, %zmm0, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm10, %zmm11, %zmm12, %zmm13, %zmm15, %zmm16, %zmm17, %k1, no_reduction, %zmm25, %zmm24, %zmm26, NROUNDS)      \
        add             $128, %rax;             \
        add             $112, %r11;             \
        sub             $112, %r13;             \
	.ifc INSTANCE_TYPE, multi_call; \
        mov             %r13, PBlockLen(GDATA_CTX);     \
        vmovdqu64       %xmm8, PBlockEncKey(GDATA_CTX); \
        .endif;         \
18:; \
        vextracti32x4   $3, %zmm18, XWORD(%zmm28);      \
        vpshufb         XWORD(%zmm29), XWORD(%zmm28), XWORD(%zmm28);      \
        .ifc INSTANCE_TYPE, multi_call; \
        cmpq            $0, PBlockLen(GDATA_CTX);       \
        jz              19f;   \
        vextracti32x4   $3, %zmm2, XWORD(%zmm11);       \
	GHASH_LAST_7(GDATA_KEY, %zmm2, %zmm1, %zmm0, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm10, %xmm14, %k1, %r10, %zmm24, %zmm25, %zmm26)      \
        vpxorq          XWORD(%zmm11), %xmm14, %xmm14; \
        jmp             20f;    \
19:;          \
	.endif;         \
	GHASH_LAST_8(GDATA_KEY, %zmm2, %zmm1, %zmm0, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %xmm14, %zmm24, %zmm25, %zmm26)      \
20:;	\
	vmovdqu64       XWORD(%zmm28), CurCount(GDATA_CTX);     \
        vmovdqu64       %xmm14, (GDATA_CTX);    \
21:;

#define simd_store_avx(DST, SRC, SIZE, TMP, IDX)        \
        xor IDX, IDX;           \
        test    $16, SIZE;      \
        jz      lt161;           \
        vmovdqu SRC, (DST);     \
        jmp     end;            \
lt161:;  \
        test    $8, SIZE;       \
        jz      lt81;            \
        vmovq   SRC, (DST, IDX, 1);     \
        vpsrldq $8, SRC, SRC;   \
        add     $8, IDX;        \
lt81:;   \
        vmovq   SRC, TMP;       \
        test    $4, SIZE;       \
        jz      lt41;            \
        mov     DWORD(TMP), (DST, IDX, 1);      \
        shr     $32, TMP;       \
        add     $4, IDX;        \
lt41:;   \
        test    $2, SIZE;       \
        jz      lt21;            \
        mov     WORD(TMP), (DST, IDX, 1);   \
        shr     $16, TMP;       \
        add     $2, IDX;        \
lt21:;\
        test    $1, SIZE;          \
        jz end1; \
        mov     BYTE(TMP), (DST, IDX, 1);       \
end1:;

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

        ret

.global aes_keyexp_192_enc_vaes_avx512

aes_keyexp_192_enc_vaes_avx512:
	vmovq 16(KEY), %xmm7
        vmovq %xmm7, 16(EXP_ENC_KEYS)
        vpshufd $0x4f, %xmm7, %xmm4
        vmovdqu (KEY), %xmm1
        vmovdqu %xmm1, (EXP_ENC_KEYS)

        vpxor %xmm3, %xmm3, %xmm3
        vpxor %xmm6, %xmm6, %xmm6

	vaeskeygenassist $0x1, %xmm4, %xmm2
        key_expansion_1_192_avx(24)
                key_expansion_2_192_avx(40)

	vaeskeygenassist $0x2, %xmm4, %xmm2
        key_expansion_1_192_avx(48)
                key_expansion_2_192_avx(64)

	vaeskeygenassist $0x4, %xmm4, %xmm2
        key_expansion_1_192_avx(72)
                key_expansion_2_192_avx(88)

        vaeskeygenassist $0x8, %xmm4, %xmm2
        key_expansion_1_192_avx(96)
                key_expansion_2_192_avx(112)

	vaeskeygenassist $0x10, %xmm4, %xmm2
        key_expansion_1_192_avx(120)
                key_expansion_2_192_avx(136)

        vaeskeygenassist $0x20, %xmm4, %xmm2
        key_expansion_1_192_avx(144)
                key_expansion_2_192_avx(160)

        vaeskeygenassist $0x40, %xmm4, %xmm2
        key_expansion_1_192_avx(168)
                key_expansion_2_192_avx(184)

        vaeskeygenassist $0x80, %xmm4, %xmm2
        key_expansion_1_192_avx(192)

        ret

.global aes_keyexp_256_enc_vaes_avx512

aes_keyexp_256_enc_vaes_avx512:
	vmovdqu (KEY), %xmm1
        vmovdqa %xmm1, (EXP_ENC_KEYS)

        vmovdqu 16(KEY), %xmm4
        vmovdqa %xmm4, 16(EXP_ENC_KEYS)

        vpxor %xmm3, %xmm3, %xmm3

	vaeskeygenassist $0x1, %xmm4, %xmm2
        key_expansion_256_avx
	vmovdqa	%xmm1, 16*2(EXP_ENC_KEYS)

	vaeskeygenassist $0x1, %xmm1, %xmm2
        key_expansion_256_avx_2
        vmovdqa %xmm4, 16*3(EXP_ENC_KEYS)

	vaeskeygenassist $0x2, %xmm4, %xmm2
        key_expansion_256_avx
        vmovdqa %xmm1, 16*4(EXP_ENC_KEYS)

        vaeskeygenassist $0x2, %xmm1, %xmm2
        key_expansion_256_avx_2
        vmovdqa %xmm4, 16*5(EXP_ENC_KEYS)

	vaeskeygenassist $0x4, %xmm4, %xmm2
        key_expansion_256_avx
        vmovdqa %xmm1, 16*6(EXP_ENC_KEYS)

        vaeskeygenassist $0x4, %xmm1, %xmm2
        key_expansion_256_avx_2
        vmovdqa %xmm4, 16*7(EXP_ENC_KEYS)

	vaeskeygenassist $0x8, %xmm4, %xmm2
        key_expansion_256_avx
        vmovdqa %xmm1, 16*8(EXP_ENC_KEYS)

        vaeskeygenassist $0x8, %xmm1, %xmm2
        key_expansion_256_avx_2
        vmovdqa %xmm4, 16*9(EXP_ENC_KEYS)

	vaeskeygenassist $0x10, %xmm4, %xmm2
        key_expansion_256_avx
        vmovdqa %xmm1, 16*10(EXP_ENC_KEYS)

        vaeskeygenassist $0x10, %xmm1, %xmm2
        key_expansion_256_avx_2
        vmovdqa %xmm4, 16*11(EXP_ENC_KEYS)

	vaeskeygenassist $0x20, %xmm4, %xmm2
        key_expansion_256_avx
        vmovdqa %xmm1, 16*12(EXP_ENC_KEYS)

        vaeskeygenassist $0x20, %xmm1, %xmm2
        key_expansion_256_avx_2
        vmovdqa %xmm4, 16*13(EXP_ENC_KEYS)

	vaeskeygenassist $0x40, %xmm4, %xmm2
        key_expansion_256_avx
        vmovdqa %xmm1, 16*14(EXP_ENC_KEYS)

	ret

.global aes_gcm_precomp_128_vaes_avx512

aes_gcm_precomp_128_vaes_avx512:
	FUNC_SAVE()
	vpxor   %xmm6, %xmm6, %xmm6
	ENCRYPT_SINGLE_BLOCK(%rdi, %xmm6, 9)

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
	ret

.global aes_gcm_precomp_192_vaes_avx512

aes_gcm_precomp_192_vaes_avx512:
        FUNC_SAVE()
        vpxor   %xmm6, %xmm6, %xmm6
        ENCRYPT_SINGLE_BLOCK(%rdi, %xmm6, 11)

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
        ret

.global aes_gcm_precomp_256_vaes_avx512

aes_gcm_precomp_256_vaes_avx512:
        FUNC_SAVE()
        vpxor   %xmm6, %xmm6, %xmm6
        ENCRYPT_SINGLE_BLOCK(%rdi, %xmm6, 13)

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
        ret

.global aes_gcm_init_vaes_avx512
aes_gcm_init_vaes_avx512:
	FUNC_SAVE()

	GCM_INIT(%rdi, %rsi, %rdx, %r8, %r9, %r10, %r11, %r12, %k1, %xmm14, %xmm2, %zmm1, %zmm2, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm8, %zmm9, %zmm10, NULL, 21)

        FUNC_RESTORE()
        ret

.global aes_gcm_init_var_iv_vaes_avx512

aes_gcm_init_var_iv_vaes_avx512:
	FUNC_SAVE()

	cmp     $12, %rcx
        je      iv_len_12_init_IV

        GCM_INIT(%rdi, %rsi, %rdx, %r8, %r9, %r10, %r11, %r12, %k1, %xmm14, %xmm2, %zmm1, %zmm11, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm8, %zmm9, %zmm10, %rcx, 22)

        jmp exit_init_IV

iv_len_12_init_IV:
        GCM_INIT(%rdi, %rsi, %rdx, %r8, %r9, %r10, %r11, %r12, %k1, %xmm14, %xmm2, %zmm1, %zmm11, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm8, %zmm9, %zmm10, NULL, 21)

exit_init_IV:
        FUNC_RESTORE()
        ret

.global aes_gcm_enc_var_init_128_vaes_avx512

aes_gcm_enc_var_init_128_vaes_avx512:
        FUNC_SAVE()

        cmp     $12, arg7
        je      iv_len_12_enc_IV_128

        GCM_INIT(arg1, arg2, arg6, arg8, arg9, %r10, %r11, %r12, %k1, %xmm14, %xmm2, %zmm1, %zmm11, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm8, %zmm9, %zmm10, arg7, 22)

        jmp	skip_iv_len_12_enc_IV_128

iv_len_12_enc_IV_128:
        GCM_INIT(arg1, arg2, arg6, arg8, arg9, %r10, %r11, %r12, %k1, %xmm14, %xmm2, %zmm1, %zmm11, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm8, %zmm9, %zmm10, NULL, 21)

skip_iv_len_12_enc_IV_128:
	GCM_ENC_DEC(arg1, arg2, arg3, arg4, arg5, ENC, single_call, 9)
        GCM_COMPLETE(arg1, arg2, arg10, arg11, ENC, single_call, 9)

exit_enc_IV_128:
        FUNC_RESTORE()
        ret

.global aes_gcm_enc_var_init_192_vaes_avx512

aes_gcm_enc_var_init_192_vaes_avx512:
        FUNC_SAVE()

        cmp     $12, arg7
        je      iv_len_12_enc_IV_192

        GCM_INIT(arg1, arg2, arg6, arg8, arg9, %r10, %r11, %r12, %k1, %xmm14, %xmm2, %zmm1, %zmm11, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm8, %zmm9, %zmm10, arg7, 22)

        jmp     skip_iv_len_12_enc_IV_192

iv_len_12_enc_IV_192:
        GCM_INIT(arg1, arg2, arg6, arg8, arg9, %r10, %r11, %r12, %k1, %xmm14, %xmm2, %zmm1, %zmm11, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm8, %zmm9, %zmm10, NULL, 21)

skip_iv_len_12_enc_IV_192:
        GCM_ENC_DEC(arg1, arg2, arg3, arg4, arg5, ENC, single_call, 11)
        GCM_COMPLETE(arg1, arg2, arg10, arg11, ENC, single_call, 11)

exit_enc_IV_192:
        FUNC_RESTORE()
        ret

.global aes_gcm_enc_var_init_256_vaes_avx512

aes_gcm_enc_var_init_256_vaes_avx512:
        FUNC_SAVE()

        cmp     $12, arg7
        je      iv_len_12_enc_IV_256

        GCM_INIT(arg1, arg2, arg6, arg8, arg9, %r10, %r11, %r12, %k1, %xmm14, %xmm2, %zmm1, %zmm11, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm8, %zmm9, %zmm10, arg7, 22)

        jmp     skip_iv_len_12_enc_IV_256

iv_len_12_enc_IV_256:
        GCM_INIT(arg1, arg2, arg6, arg8, arg9, %r10, %r11, %r12, %k1, %xmm14, %xmm2, %zmm1, %zmm11, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm8, %zmm9, %zmm10, NULL, 21)

skip_iv_len_12_enc_IV_256:
        GCM_ENC_DEC(arg1, arg2, arg3, arg4, arg5, ENC, single_call, 13)
        GCM_COMPLETE(arg1, arg2, arg10, arg11, ENC, single_call, 13)

exit_enc_IV_256:
        FUNC_RESTORE()
        ret

.global aes_gcm_dec_var_init_128_vaes_avx512

aes_gcm_dec_var_init_128_vaes_avx512:
        FUNC_SAVE()

        cmp     $12, arg7
        je      iv_len_12_dec_IV_128

        GCM_INIT(arg1, arg2, arg6, arg8, arg9, %r10, %r11, %r12, %k1, %xmm14, %xmm2, %zmm1, %zmm11, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm8, %zmm9, %zmm10, arg7, 22)

        jmp     skip_iv_len_12_dec_IV_128

iv_len_12_dec_IV_128:
        GCM_INIT(arg1, arg2, arg6, arg8, arg9, %r10, %r11, %r12, %k1, %xmm14, %xmm2, %zmm1, %zmm11, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm8, %zmm9, %zmm10, NULL, 21)

skip_iv_len_12_dec_IV_128:
        GCM_ENC_DEC(arg1, arg2, arg3, arg4, arg5, DEC, single_call, 9)
        GCM_COMPLETE(arg1, arg2, arg10, arg11, DEC, single_call, 9)

exit_dec_IV_128:
        FUNC_RESTORE()
        ret

.global aes_gcm_dec_var_init_192_vaes_avx512

aes_gcm_dec_var_init_192_vaes_avx512:
        FUNC_SAVE()

        cmp     $12, arg7
        je      iv_len_12_dec_IV_192

        GCM_INIT(arg1, arg2, arg6, arg8, arg9, %r10, %r11, %r12, %k1, %xmm14, %xmm2, %zmm1, %zmm11, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm8, %zmm9, %zmm10, arg7, 22)

        jmp     skip_iv_len_12_dec_IV_192

iv_len_12_dec_IV_192:
        GCM_INIT(arg1, arg2, arg6, arg8, arg9, %r10, %r11, %r12, %k1, %xmm14, %xmm2, %zmm1, %zmm11, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm8, %zmm9, %zmm10, NULL, 21)

skip_iv_len_12_dec_IV_192:
        GCM_ENC_DEC(arg1, arg2, arg3, arg4, arg5, DEC, single_call, 11)
        GCM_COMPLETE(arg1, arg2, arg10, arg11, DEC, single_call, 11)

exit_dec_IV_192:
        FUNC_RESTORE()
        ret

.global aes_gcm_dec_var_init_256_vaes_avx512

aes_gcm_dec_var_init_256_vaes_avx512:
        FUNC_SAVE()

        cmp     $12, arg7
        je      iv_len_12_dec_IV_256

        GCM_INIT(arg1, arg2, arg6, arg8, arg9, %r10, %r11, %r12, %k1, %xmm14, %xmm2, %zmm1, %zmm11, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm8, %zmm9, %zmm10, arg7, 22)

        jmp     skip_iv_len_12_dec_IV_256

iv_len_12_dec_IV_256:
        GCM_INIT(arg1, arg2, arg6, arg8, arg9, %r10, %r11, %r12, %k1, %xmm14, %xmm2, %zmm1, %zmm11, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm8, %zmm9, %zmm10, NULL, 21)

skip_iv_len_12_dec_IV_256:
        GCM_ENC_DEC(arg1, arg2, arg3, arg4, arg5, DEC, single_call, 13)
        GCM_COMPLETE(arg1, arg2, arg10, arg11, DEC, single_call, 13)

exit_dec_IV_256:
        FUNC_RESTORE()
        ret

.global aes_gcm_enc_128_finalize_vaes_avx512

aes_gcm_enc_128_finalize_vaes_avx512:
        FUNC_SAVE()
        GCM_COMPLETE(%rdi, %rsi, %rdx, %rcx, ENC, multi_call, 9)
        FUNC_RESTORE()

        ret

.global aes_gcm_enc_192_finalize_vaes_avx512

aes_gcm_enc_192_finalize_vaes_avx512:
        FUNC_SAVE()
        GCM_COMPLETE(%rdi, %rsi, %rdx, %rcx, ENC, multi_call, 11)
        FUNC_RESTORE()

        ret

.global aes_gcm_enc_256_finalize_vaes_avx512

aes_gcm_enc_256_finalize_vaes_avx512:
        FUNC_SAVE()
        GCM_COMPLETE(%rdi, %rsi, %rdx, %rcx, ENC, multi_call, 13)
        FUNC_RESTORE()

        ret

.global aes_gcm_dec_128_finalize_vaes_avx512

aes_gcm_dec_128_finalize_vaes_avx512:
        FUNC_SAVE()
        GCM_COMPLETE(%rdi, %rsi, %rdx, %rcx, DEC, multi_call, 9)
        FUNC_RESTORE()

        ret

.global aes_gcm_dec_192_finalize_vaes_avx512

aes_gcm_dec_192_finalize_vaes_avx512:
        FUNC_SAVE()
        GCM_COMPLETE(%rdi, %rsi, %rdx, %rcx, DEC, multi_call, 11)
        FUNC_RESTORE()

        ret

.global aes_gcm_dec_256_finalize_vaes_avx512

aes_gcm_dec_256_finalize_vaes_avx512:
        FUNC_SAVE()
        GCM_COMPLETE(%rdi, %rsi, %rdx, %rcx, DEC, multi_call, 13)
        FUNC_RESTORE()

        ret

.global aes_gcm_enc_128_update_vaes_avx512

aes_gcm_enc_128_update_vaes_avx512:
        FUNC_SAVE()

        GCM_ENC_DEC(%rdi, %rsi, %rdx, %rcx, %r8, ENC, multi_call, 9)

        FUNC_RESTORE()
        ret

.global aes_gcm_enc_192_update_vaes_avx512

aes_gcm_enc_192_update_vaes_avx512:
        FUNC_SAVE()

        GCM_ENC_DEC(%rdi, %rsi, %rdx, %rcx, %r8, ENC, multi_call, 11)

        FUNC_RESTORE()
        ret

.global aes_gcm_enc_256_update_vaes_avx512

aes_gcm_enc_256_update_vaes_avx512:
        FUNC_SAVE()

        GCM_ENC_DEC(%rdi, %rsi, %rdx, %rcx, %r8, ENC, multi_call, 13)

        FUNC_RESTORE()
        ret

.global aes_gcm_dec_128_update_vaes_avx512

aes_gcm_dec_128_update_vaes_avx512:
        FUNC_SAVE()

        GCM_ENC_DEC(%rdi, %rsi, %rdx, %rcx, %r8, DEC, multi_call, 9)

        FUNC_RESTORE()
        ret

.global aes_gcm_dec_192_update_vaes_avx512

aes_gcm_dec_192_update_vaes_avx512:
        FUNC_SAVE()

        GCM_ENC_DEC(%rdi, %rsi, %rdx, %rcx, %r8, DEC, multi_call, 11)

        FUNC_RESTORE()
        ret

.global aes_gcm_dec_256_update_vaes_avx512

aes_gcm_dec_256_update_vaes_avx512:
        FUNC_SAVE()

        GCM_ENC_DEC(%rdi, %rsi, %rdx, %rcx, %r8, DEC, multi_call, 13)

        FUNC_RESTORE()
        ret

.global aes_gcm_enc_128_vaes_avx512

aes_gcm_enc_128_vaes_avx512:
        FUNC_SAVE()

        GCM_INIT(arg1, arg2, arg6, arg7, arg8, %r10, %r11, %r12, %k1, %xmm14, %xmm2, %zmm1, %zmm2, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm8, %zmm9, %zmm10, NULL, 21)
        GCM_ENC_DEC(arg1, arg2, arg3, arg4, arg5, ENC, single_call, 9)
        GCM_COMPLETE(arg1, arg2, arg9, arg10, ENC, single_call, 9)
        FUNC_RESTORE()

	ret

.global aes_gcm_enc_192_vaes_avx512

aes_gcm_enc_192_vaes_avx512:
        FUNC_SAVE()

        GCM_INIT(arg1, arg2, arg6, arg7, arg8, %r10, %r11, %r12, %k1, %xmm14, %xmm2, %zmm1, %zmm2, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm8, %zmm9, %zmm10, NULL, 21)
        GCM_ENC_DEC(arg1, arg2, arg3, arg4, arg5, ENC, single_call, 11)
        GCM_COMPLETE(arg1, arg2, arg9, arg10, ENC, single_call, 11)
        FUNC_RESTORE()

	ret

.global aes_gcm_enc_256_vaes_avx512

aes_gcm_enc_256_vaes_avx512:
        FUNC_SAVE()

        GCM_INIT(arg1, arg2, arg6, arg7, arg8, %r10, %r11, %r12, %k1, %xmm14, %xmm2, %zmm1, %zmm2, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm8, %zmm9, %zmm10, NULL, 21)
        GCM_ENC_DEC(arg1, arg2, arg3, arg4, arg5, ENC, single_call, 13)
        GCM_COMPLETE(arg1, arg2, arg9, arg10, ENC, single_call, 13)
        FUNC_RESTORE()

        ret

.global aes_gcm_dec_128_vaes_avx512

aes_gcm_dec_128_vaes_avx512:
        FUNC_SAVE()

        GCM_INIT(arg1, arg2, arg6, arg7, arg8, %r10, %r11, %r12, %k1, %xmm14, %xmm2, %zmm1, %zmm2, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm8, %zmm9, %zmm10, NULL, 21)
        GCM_ENC_DEC(arg1, arg2, arg3, arg4, arg5, DEC, single_call, 9)
        GCM_COMPLETE(arg1, arg2, arg9, arg10, DEC, single_call, 9)
        FUNC_RESTORE()

        ret

.global aes_gcm_dec_192_vaes_avx512

aes_gcm_dec_192_vaes_avx512:
        FUNC_SAVE()

        GCM_INIT(arg1, arg2, arg6, arg7, arg8, %r10, %r11, %r12, %k1, %xmm14, %xmm2, %zmm1, %zmm2, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm8, %zmm9, %zmm10, NULL, 21)
        GCM_ENC_DEC(arg1, arg2, arg3, arg4, arg5, DEC, single_call, 11)
        GCM_COMPLETE(arg1, arg2, arg9, arg10, DEC, single_call, 11)
        FUNC_RESTORE()

	ret

.global aes_gcm_dec_256_vaes_avx512

aes_gcm_dec_256_vaes_avx512:
        FUNC_SAVE()

        GCM_INIT(arg1, arg2, arg6, arg7, arg8, %r10, %r11, %r12, %k1, %xmm14, %xmm2, %zmm1, %zmm2, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm8, %zmm9, %zmm10, NULL, 21)
        GCM_ENC_DEC(arg1, arg2, arg3, arg4, arg5, DEC, single_call, 13)
        GCM_COMPLETE(arg1, arg2, arg9, arg10, DEC, single_call, 13)
        FUNC_RESTORE()

        ret

.global ghash_vaes_avx512

ghash_vaes_avx512:
        FUNC_SAVE()

        CALC_AAD_HASH(%rsi, %rdx, %xmm0, %rdi, %zmm1, %zmm2, %zmm3, %zmm4, %zmm5, %zmm6, %zmm7, %zmm8, %zmm9, %zmm10, %r10, %r11, %r12, %k1)

        vpshufb SHUF_MASK(%rip), %xmm0, %xmm0

        simd_store_avx(%rcx, %xmm0, %r8, %r12, %rax)

        FUNC_RESTORE()

        ret
