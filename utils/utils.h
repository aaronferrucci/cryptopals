#ifndef UTILS_H
#define UTILS_H
unsigned char *randomX(unsigned char *data, size_t len);
unsigned char *random16(unsigned char data[16]);
unsigned char nibble_convert(char c);
unsigned char hex_convert(char *s);
void decode_hex_string(char *s, unsigned char *bytes, int byte_count);
size_t count_bits(unsigned char c);
size_t hamming(char *s1, char *s2, size_t len);

// allocates memory, decodes input data into it, returns a pointer to 
// decoded data. Caller calls free(). len is set to the output data length.
unsigned char *base64_decode(unsigned char *base64_data, size_t *len);

float score_etaoin(unsigned char *data, int start, int stride, int len);
unsigned char max_xor_key(unsigned char *data, int start, int stride, int len);
void xor_decode(unsigned char *data, unsigned char key, int len);
void repeating_xor_decode(unsigned char *data, unsigned char *key, int len);
void print16(unsigned char *data);
void printX(unsigned char *data, size_t len);

typedef struct {
  unsigned char letter; 
  float frequency; // in [0, 1]
  unsigned int count;
} t_letter_frequency;

#define EQ_16BYTE(pa, pb) ((*(__uint128_t*)(pa)) == (*(__uint128_t*)(pb)))
#endif // UTILS_H
