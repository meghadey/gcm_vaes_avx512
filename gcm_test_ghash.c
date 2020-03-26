#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define GCM_ENC_KEY_LEN 16
#define GCM_KEY_SETS    (15) 
#define GCM_BLOCK_LEN   16

struct gcm_key_data {
        uint8_t expanded_keys[GCM_ENC_KEY_LEN * GCM_KEY_SETS];
        union {
                struct {
                        uint8_t shifted_hkey[GCM_ENC_KEY_LEN * 48];
                } vaes_avx512;
        } ghash_keys;
}
__attribute__((aligned(64)));

struct gcm_context_data {
        /* init, update and finalize context data */
        uint8_t  aad_hash[GCM_BLOCK_LEN];
        uint64_t aad_length;
        uint64_t in_length;
        uint8_t  partial_block_enc_key[GCM_BLOCK_LEN];
        uint8_t  orig_IV[GCM_BLOCK_LEN];
        uint8_t  current_counter[GCM_BLOCK_LEN];
        uint64_t partial_block_length;
};

extern void ghash_vaes_avx512(struct gcm_key_data *key_data, const void *in,
                  const uint64_t in_len, void *tag,
                  const uint64_t tag_len);
extern void aes_gcm_precomp_128_vaes_avx512(struct gcm_key_data *key_data);
extern void aes_keyexp_128_enc_vaes_avx512(const void *key, void *enc_exp_keys);
extern void aes_gcm_init_var_iv_128_vaes_avx512(struct gcm_key_data *key_data,
                                struct gcm_context_data *context_data,
                                const uint8_t *iv, const uint64_t iv_len,
                                const uint8_t *aad, const uint64_t aad_len);
extern void aes_gcm_enc_128_finalize_vaes_avx512(struct gcm_key_data *key_data,
                                     struct gcm_context_data *context_data,
                                     uint8_t *auth_tag, uint64_t auth_tag_len);

static uint8_t K12[] = {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
};
static uint8_t P12[] = {
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
        0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
        0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
        0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
        0xba, 0x63, 0x7b, 0x39
};
static uint8_t A12[] = {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2
};
static uint8_t IV12[] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad
};
static uint8_t C12[] =  {
        0xc3, 0x76, 0x2d, 0xf1, 0xca, 0x78, 0x7d, 0x32,
        0xae, 0x47, 0xc1, 0x3b, 0xf1, 0x98, 0x44, 0xcb,
        0xaf, 0x1a, 0xe1, 0x4d, 0x0b, 0x97, 0x6a, 0xfa,
        0xc5, 0x2f, 0xf7, 0xd7, 0x9b, 0xba, 0x9d, 0xe0,
        0xfe, 0xb5, 0x82, 0xd3, 0x39, 0x34, 0xa4, 0xf0,
        0x95, 0x4c, 0xc2, 0x36, 0x3b, 0xc7, 0x3f, 0x78,
        0x62, 0xac, 0x43, 0x0e, 0x64, 0xab, 0xe4, 0x99,
        0xf4, 0x7c, 0x9b, 0x1f
};
static uint8_t T12[] =  {
        0x3a, 0x33, 0x7d, 0xbf, 0x46, 0xa7, 0x92, 0xc4,
        0x5e, 0x45, 0x49, 0x13, 0xfe, 0x2e, 0xa8, 0xf2
};
#define A12_len sizeof(A12)

struct gcm_ctr_vector {
        const uint8_t* K;          // AES Key
        uint64_t       Klen;       // length of key in bits
        const uint8_t* IV;         // initial value used by GCM
        uint64_t       IVlen;      // length of IV in bytes
        const uint8_t* A;          // additional authenticated data
        uint64_t       Alen;       // length of AAD in bytes
        const uint8_t* P;          // Plain text
        uint64_t       Plen;       // length of our plaintext
        //outputs of encryption
        const uint8_t* C;          // same length as PT
        const uint8_t* T;          // Authenication tag
        uint8_t        Tlen;       // AT length can be 0 to 128bits
};

#define KBITS(K)    (sizeof(K))

#define vector(N)                                                       \
        K##N, (KBITS(K##N)), IV##N, sizeof(IV##N), A##N, A##N##_len,   \
                        P##N, sizeof(P##N), C##N, T##N, sizeof(T##N)

static const struct gcm_ctr_vector gcm_vectors = {
        vector(12)
};

static void aes_gcm_pre_128_vaes_avx512(const void *key, struct gcm_key_data *key_data)
{
	aes_keyexp_128_enc_vaes_avx512(key, key_data->expanded_keys);
        aes_gcm_precomp_128_vaes_avx512(key_data);
}

static int test_ghash(void)
{
        int is_error = 0;
	struct gcm_key_data gdata_key;
	struct gcm_ctr_vector const *vector = &gcm_vectors;
	struct gcm_context_data ctx;
	int i;
	uint8_t *T_test = NULL;

	T_test = malloc(vector->Tlen);
        if (T_test == NULL) {
                fprintf(stderr, "Can't allocate tag memory\n");
                is_error = 1;
                goto test_gcm_vectors_exit;
        }

	printf("gcm_context_data %lx\n", &ctx); 
	aes_gcm_pre_128_vaes_avx512(vector->K, &gdata_key);
	aes_gcm_init_var_iv_128_vaes_avx512(&gdata_key, &ctx,
					    vector->IV, vector->IVlen,
					    vector->A, vector->Alen);
	aes_gcm_enc_128_finalize_vaes_avx512(&gdata_key, &ctx, T_test, vector->Tlen);
	for(i = 0; i < 16*48; i++)
                printf("%x ", gdata_key.ghash_keys.vaes_avx512.shifted_hkey[i]);

	printf("Megha ctx->aad_hash:\n");
	for(i = 0; i < 16; i++)
                printf("%x ", ctx.aad_hash[i]);
        printf("\n");
        printf("Megha ctx->aad_length %lx\n", ctx.aad_length);
        printf("Megha ctx->in_length %lx\n", ctx.in_length);
	printf("Megha ctx->partial_block_enc_key:\n");
        for(i = 0; i < 16; i++)
                printf("%x ", ctx.partial_block_enc_key[i]);
        printf("\n");
	printf("Megha ctx->orig_IV:\n");
        for(i = 0; i < 16; i++)
                printf("%x ", ctx.orig_IV[i]);
        printf("\n");
	printf("Megha ctx->current_counter:\n");
        for(i = 0; i < 16; i++)
                printf("%x ", ctx.current_counter[i]);
        printf("\n");
        printf("Megha ctx->partial_block_length %lx\n", ctx.partial_block_length);
test_gcm_vectors_exit:
        return is_error;
}

void main()
{
	int error = 0;

	error = test_ghash();
}
