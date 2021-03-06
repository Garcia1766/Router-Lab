#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(for response) and 0(for request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

bool checkMask(const uint32_t mask) {
    uint32_t p = 0, m = 1;
    for (; p < 32 && !(mask & m); p++, m <<= 1);
    for (; p < 32; p++, m <<= 1)
        if (!(mask & m))
            return false;
    return true;
}

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
    uint16_t total_len = ((uint16_t) packet[2] << 8) + packet[3];
    if (total_len > len) return false;

    uint32_t header_len = packet[0] & 0x0F;
    header_len <<= 2; // IPV4 header length
    uint32_t p = header_len + 8; // UDP length = 8, p -> Command

    if (packet[p] != 1 && packet[p] != 2) return false; // Check if Command == 1 or 2
    output->command = packet[p];
    uint16_t expected_family = output->command == 1 ? 0 : 2;

    p += 1; // p -> Version
    if (packet[p] != 2) return false; // Check if Version == 2

    p += 3; // p -> IP Address
    uint32_t i = 0;
    for (; p < total_len; i++) {
        uint16_t family = ((uint16_t) packet[p] << 8) + packet[p + 1];
        if (family != expected_family) return false; // Check if family == expected_family

        p += 2; // p -> Tag
        uint16_t tag = ((uint16_t) packet[p] << 8) + packet[p + 1];
        if (tag != 0) return false; // Check if tag == 0

        p += 2; // p -> Address
        output->entries[i].addr = 0;
        for (int j = 3; j >= 0; j--)
            output->entries[i].addr = (output->entries[i].addr << 8) + packet[p + j];

        p += 4; // p -> Mask
        output->entries[i].mask = 0;
        for (int j = 3; j >= 0; j--)
            output->entries[i].mask = (output->entries[i].mask << 8) + packet[p + j];
        if (!checkMask(ntohl(output->entries[i].mask))) return false; // Check if Mask is valid

        p += 4; // p -> NextHop
        output->entries[i].nexthop = 0;
        for (int j = 3; j >= 0; j--)
            output->entries[i].nexthop = (output->entries[i].nexthop << 8) + packet[p + j];

        p += 4; // p -> Metric
        output->entries[i].metric = 0;
        for (int j = 3; j >= 0; j--)
            output->entries[i].metric = (output->entries[i].metric << 8) + packet[p + j];
        if (ntohl(output->entries[i].metric) < 1 || 16 < ntohl(output->entries[i].metric))
            return false; // Check if 1 <= Metric <= 16

        p += 4; // p -> Family
    }
    output->numEntries = i;
    return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
    buffer[0] = rip->command;
    buffer[1] = 2;
    buffer[2] = buffer[3] = 0;
    uint16_t family = rip->command == 1 ? 0 : 2;
    uint32_t p = 4;
    for (int i = 0; i < rip->numEntries; i++) {
        buffer[p++] = 0;
        buffer[p++] = family;
        buffer[p++] = buffer[p++] = 0;
        for (int j = 0; j < 4; j++)
            buffer[p++] = (rip->entries[i].addr >> (8 * j)) & 0xFF;
        for (int j = 0; j < 4; j++)
            buffer[p++] = (rip->entries[i].mask >> (8 * j)) & 0xFF;
        for (int j = 0; j < 4; j++)
            buffer[p++] = (rip->entries[i].nexthop >> (8 * j)) & 0xFF;
        for (int j = 0; j < 4; j++)
            buffer[p++] = (rip->entries[i].metric >> (8 * j)) & 0xFF;
    }
    return p;
}
