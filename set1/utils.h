#ifndef UTILS_H
#define UTILS_H
unsigned char nibble_convert(char c);
unsigned char hex_convert(char *s);
void decode_hex_string(char *s, unsigned char *bytes, int byte_count);
size_t count_bits(unsigned char c);
size_t hamming(char *s1, char *s2, size_t len);
unsigned char *base64_decode(unsigned char *base64_data, size_t *len);
#endif // UTILS_H
