#ifndef MISC_H
#define MISC_H

void parse_hostport(char* hostport, char** host, int* port);

unsigned base64_decode(const char *src, unsigned char **outptr);

#endif // MISC_H
