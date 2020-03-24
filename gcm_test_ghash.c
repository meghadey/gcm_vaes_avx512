#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define GCM_ENC_KEY_LEN 16
#define GCM_KEY_SETS    (15) 

struct gcm_key_data {
        uint8_t expanded_keys[GCM_ENC_KEY_LEN * GCM_KEY_SETS];
        union {
                struct {
                        uint8_t shifted_hkey[GCM_ENC_KEY_LEN * 48];
                } vaes_avx512;
        } ghash_keys;
}
__attribute__((aligned(64)));

extern void ghash_vaes_avx512(struct gcm_key_data *key_data, const void *in,
                  const uint64_t in_len, void *tag,
                  const uint64_t tag_len);
extern void aes_gcm_precomp_128_vaes_avx512(struct gcm_key_data *key_data);
extern void aes_keyexp_128_enc_vaes_avx512(const void *key, void *enc_exp_keys);

/* GHASH vectors */
static uint8_t K23[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static uint8_t P23[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

static uint8_t T23[] = {
        0x9E, 0xE5, 0xA5, 0x1F, 0xBE, 0x28, 0xA1, 0x15,
        0x3E, 0xF1, 0x96, 0xF5, 0x0B, 0xBF, 0x03, 0xCA
};

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

#define ghash_vector(N)                                                 \
        K##N, (KBITS(K##N)), NULL, 0, NULL, 0, P##N, sizeof(P##N),     \
                        NULL, T##N, sizeof(T##N)

static const struct gcm_ctr_vector ghash_vectors = {
        ghash_vector(23)
};

static int check_data(const uint8_t *test, const uint8_t *expected,
                      uint64_t len, const char *data_name)
{
        int mismatch;
        int is_error = 0;

        mismatch = memcmp(test, expected, len);
        if (mismatch) {
                uint64_t a;

                is_error = 1;
                printf("expected results don't match %s \t\t", data_name);
                for (a = 0; a < len; a++) {
			printf("test[a] is %x expected[a] is %x\n", test[a], expected[a]);
                        if (test[a] != expected[a]) {
                                printf(" '%x' != '%x' at %llx of %llx\n",
                                       test[a], expected[a],
                                       (unsigned long long) a,
                                       (unsigned long long) len);
                        }
                }
        }
        return is_error;
}

static void aes_gcm_pre_128_vaes_avx512(const void *key, struct gcm_key_data *key_data)
{
	aes_keyexp_128_enc_vaes_avx512(key, key_data->expanded_keys);
        aes_gcm_precomp_128_vaes_avx512(key_data);
}

static int test_ghash(void)
{
        int is_error = 0;
        uint8_t T_test[16];
	struct gcm_key_data gdata_key = {0};
	struct gcm_ctr_vector const *vector = &ghash_vectors;
        
	aes_gcm_pre_128_vaes_avx512(vector->K, &gdata_key);
        ghash_vaes_avx512(&gdata_key, vector->P, vector->Plen,
                          T_test, vector->Tlen);
        is_error |= check_data(T_test, vector->T, vector->Tlen, "generated tag (T)");

        return is_error;
}

void main()
{
	int error = 0;

	error = test_ghash();
}
