#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 改变一个 uint8_t 型数组的连续两个字节的值
 * @param out 需要改变的数组
 * @param p 改变的位置
 * @param v 改成的 uint16_t 值
 */
/*void put_uint16(uint8_t *out, size_t p, uint16_t v) {
    out[p] = (v >> 8) & 0xFF;
    out[p + 1] = (v >> 0) & 0xFF;
}*/

/**
 * @brief 计算 IP 头的校验和
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 计算得出的 IP 头的校验和
 */
/*uint16_t calculateIPChecksum(uint8_t *packet) {
    uint8_t header_len = packet[0] & 0x0F; // number of 4-bytes
    uint8_t packet10 = packet[10]; uint8_t packet11 = packet[11];
    packet[10] = packet[11] = 0;
    uint32_t sum = 0;
    for (size_t i = 0; i < (uint32_t) header_len << 1; i++)
        sum += packet[2 * i] << 8 | packet[2 * i + 1];
    while (sum >> 16 > 0)
        sum = (sum >> 16) + (sum & 0xFFFF);
    sum = ~sum & 0xFFFF;
    packet[10] = packet10; packet[11] = packet11;
    // packet[10] = sum >> 8; packet[11] = sum & 0xFF;
    return sum;
}*/

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
/*bool validateIPChecksum(uint8_t *packet, size_t len) {
    uint16_t old_sum = (uint16_t) packet[10] << 8 | packet[11];
    uint16_t new_sum = calculateIPChecksum(packet);
    return new_sum == old_sum;
}*/
