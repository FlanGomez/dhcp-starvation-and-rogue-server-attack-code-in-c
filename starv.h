

#ifndef STARV_H
#define STARV_H

#include "shared.h"


uint16_t checksum(void *buf, int len);
uint8_t rand_value(void);
int8_t server_starvation(int *sockfd);

#endif