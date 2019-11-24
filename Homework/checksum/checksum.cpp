#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 计算 IP 头的校验和
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 计算得出的 IP 头的校验和
 */
uint16_t calculateIPChecksum(uint8_t *packet, size_t len) {
    uint8_t header_len = packet[0] & 0x0F;
    uint16_t *ip_header = (uint16_t *) packet;
    uint16_t old_sum = ip_header[5];
    ip_header[5] = 0;
    uint32_t sum = 0;
    for (size_t i = 0; i < header_len << 1; i++)
        sum += ip_header[i];
    while (sum >> 16 > 0)
        sum = (sum >> 16) + (sum & 0xFFFF);
    ip_header[5] = old_sum;
    return ~sum & 0xFFFF;
}

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
    uint16_t *ip_header = (uint16_t *) packet;
    uint16_t old_sum = ip_header[5];
    uint16_t new_sum = calculateIPChecksum(packet, len);
    return new_sum == old_sum;
}
