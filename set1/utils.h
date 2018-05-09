#ifndef UTILS_H
#define UTILS_H
unsigned char nibble_convert(char c);
unsigned char hex_convert(char *s);
void decode_hex_string(char *s, unsigned char *bytes, int byte_count);
#endif // UTILS_H
