#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern uint16_t calculateIPChecksum(unsigned char *packet);

extern bool validateIPChecksum(uint8_t *packet, size_t len);

extern void update(bool insert, RoutingTableEntry entry);

extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index, uint32_t *metric);

extern bool forward(uint8_t *packet, size_t len);

extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);

extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);

extern RoutingTableEntry tableEntry[100];
extern uint32_t p; // 路由表总条数
extern uint32_t un_mask[33];

const uint32_t rip_multicast = 0x090000e0; // 组播IP 224.0.0.9
//macaddr_t rip_mac = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x09}; // 组播MAC
uint8_t packet[2048]; // 收到的IP包
uint8_t output[2048]; // 发出的IP包
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0202a8c0, 0x0204a8c0, 0x0205a8c0,
                                     0x0103000a};

void put_uint8(uint8_t *out, size_t p, uint8_t v) {
    out[p + 0] = (v >> 0) & 0xff;
}

extern void put_uint16(uint8_t *out, size_t p, uint16_t v);
/*
void put_uint16(uint8_t *out, size_t p, uint16_t v) {
    out[p + 0] = (v >> 8) & 0xff;
    out[p + 1] = (v >> 0) & 0xff;
}
*/

void put_uint32(uint8_t *out, size_t p, uint32_t v) {
    out[p + 0] = (v >> 24) & 0xff;
    out[p + 1] = (v >> 16) & 0xff;
    out[p + 2] = (v >> 8) & 0xff;
    out[p + 3] = (v >> 0) & 0xff;
}

uint32_t maskLength(uint32_t mask) {
    uint32_t p = 32, mm = 1;
    for (; p > 0 && !(mask & mm); p--, mm <<= 1);
    return p;
}

void debug() {
    printf("\n======== ======== ======== ======== ======== ========\n");
    printf("addr     len      ifIndex  nextHop  metric   from\n");
    printf("======== ======== ======== ======== ======== ========\n");
    for (int i = 0; i < p; i++) {
        printf("%08x %02d       %02d       %08x %02d       %02d\n", tableEntry[i].addr, tableEntry[i].len, tableEntry[i].if_index,
               tableEntry[i].nexthop, tableEntry[i].metric, tableEntry[i].from);
    }
    printf("======== ======== ======== ======== ======== ========\n\n");
}

int query_router_entry(uint32_t addr, uint32_t len) {
    for (int i = 0; i < p; ++i) {
        if (tableEntry[i].addr == addr && tableEntry[i].len == len)
            return i;
    }
    return -1;
}

int main(int argc, char *argv[]) {
    // 0a.
    int res = HAL_Init(1, addrs);
    if (res < 0) {
        return res;
    }

    // 0b. Add direct routes
    // For example:
    // 10.0.0.0/24 if 0
    // 10.0.1.0/24 if 1
    // 10.0.2.0/24 if 2
    // 10.0.3.0/24 if 3
    for (uint32_t i = 0; i < 4; i++) { // i < N_IFACE_ON_BOARD
        RoutingTableEntry entry = {
                .addr = addrs[i] & 0x00FFFFFF, // big endian
                .len = 24,        // small endian
                .if_index = i,    // small endian
                .nexthop = 0,     // big endian, means direct
                .metric = 1,
                .from = i
        };
        update(true, entry);
    }

    uint64_t last_time = 0; // 开始时间
    while (1) {
        uint64_t time = HAL_GetTicks();
        /*
        if (time > last_time + 30 * 1000) {
          // What to do?
          // send complete routing table to every interface
          // ref. RFC2453 3.8
          // multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09
          printf("30s Timer\n");
          last_time = time;
        }
        */
        if (time > last_time + 5 * 1000) {
            debug();

            for (int i = 0; i < 4; i++) {
                printf("send %08x > %08x @ %d response\n", addrs[i], rip_multicast, i);
                RipPacket resp;

                put_uint8(output, 0, 0x45); // ipv4 20字节
                put_uint8(output, 8, 0x01); // TTL
                put_uint8(output, 9, 0x11); // UDP

                put_uint32(output, 12, ntohl(addrs[i])); // 源地址
                put_uint32(output, 16, ntohl(rip_multicast)); // 目的地址

                put_uint16(output, 20, 0x0208); // UDP端口号
                put_uint16(output, 22, 0x0208); //

                resp.numEntries = 0; // 转发表项数
                resp.command = 2; // response
                for (int j = 0; j < p; j++) { // 路由表里的项全加入转发表
                    if (tableEntry[j].if_index != i) {
                        resp.entries[resp.numEntries].addr = tableEntry[j].addr;
                        resp.entries[resp.numEntries].mask = un_mask[tableEntry[j].len];
                        //resp.entries[resp.numEntries].nexthop = tableEntry[j].nexthop;
                        resp.entries[resp.numEntries].nexthop = addrs[i];
                        resp.entries[resp.numEntries].metric = ntohl(tableEntry[j].metric);
                        resp.numEntries++;
                    }
                }
                uint32_t rip_len = assemble(&resp, &output[20 + 8]);

                put_uint16(output, 2, 20 + 8 + rip_len);
                put_uint16(output, 24, 8 + rip_len);

                put_uint16(output, 10, calculateIPChecksum(output));

                macaddr_t rip_mac = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x09}; // 组播MAC地址
                HAL_SendIPPacket(i, output, 20 + 8 + rip_len, rip_mac);
            }

            last_time = time;
        }

        int mask = (1 << N_IFACE_ON_BOARD) - 1;
        macaddr_t src_mac;
        macaddr_t dst_mac;
        int if_index;
        res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac,
                                  1000, &if_index);
        if (res == HAL_ERR_EOF) {
            break;
        } else if (res < 0) {
            return res;
        } else if (res == 0) {
            // Timeout
            continue;
        } else if (res > sizeof(packet)) {
            // packet is truncated, ignore it
            continue;
        }

        // 1. validate
        if (!validateIPChecksum(packet, res)) {
            printf("Invalid IP Checksum\n");
            continue;
        }

        in_addr_t src_addr = (packet[12] << 0) | (packet[13] << 8) | (packet[14] << 16) | (packet[15] << 24);
        in_addr_t dst_addr = (packet[16] << 0) | (packet[17] << 8) | (packet[18] << 16) | (packet[19] << 24);
        // extract src_addr and dst_addr from packet
        // big endian

        // 2. check whether dst is me
        bool dst_is_me = false;
        for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
            if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
                dst_is_me = true;
                break;
            }
        }
        // TODO: Handle rip multicast address(224.0.0.9)?
        dst_is_me |= (dst_addr == rip_multicast);

        if (dst_is_me) {
            // 3a.1
            RipPacket rip;
            // check and validate
            if (disassemble(packet, res, &rip)) {
                if (rip.command == 1) { // receive a request
                    printf("recv %08x > %08x request\n", src_addr, dst_addr);
                    // 3a.3 request, ref. RFC2453 3.9.1
                    // only need to respond to whole table requests in the lab
                    RipPacket resp;

                    put_uint8(output, 0, 0x45);
                    put_uint8(output, 8, 0x01);
                    put_uint8(output, 9, 0x11);

                    put_uint32(output, 12, ntohl(addrs[if_index]));
                    put_uint32(output, 16, ntohl(src_addr));

                    put_uint16(output, 20, 0x0208);
                    put_uint16(output, 22, 0x0208);

                    resp.numEntries = 0;
                    resp.command = 2;
                    for (int i = 0; i < p; i++) {
                        if (tableEntry[i].if_index != if_index) { // 水平分割算法
                            resp.entries[resp.numEntries].addr = tableEntry[i].addr;
                            resp.entries[resp.numEntries].mask = un_mask[tableEntry[i].len];
                            resp.entries[resp.numEntries].nexthop = addrs[if_index];
                            resp.entries[resp.numEntries].metric = ntohl(tableEntry[i].metric);
                            resp.numEntries++;
                        }
                    }
                    // TODO: fill resp
                    // assemble
                    // IP
                    //output[0] = 0x45;
                    // ...
                    // UDP
                    // port = 520
                    //output[20] = 0x02;
                    //output[21] = 0x08;
                    // ...
                    // RIP
                    uint32_t rip_len = assemble(&resp, &output[20 + 8]);
                    // checksum calculation for ip and udp
                    // if you don't want to calculate udp checksum, set it to zero
                    // send it back
                    put_uint16(output, 2, 20 + 8 + rip_len);
                    put_uint16(output, 24, 8 + rip_len);

                    put_uint16(output, 10, calculateIPChecksum(output));

                    printf("send %08x > %08x response\n", addrs[if_index], src_addr);
                    HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
                } else { // receive a response
                    // 3a.2 response, ref. RFC2453 3.9.2
                    // update routing table
                    // new metric = ?
                    // update metric, if_index, nexthop
                    // what is missing from RoutingTableEntry?
                    // TODO: use query and update
                    // triggered updates? ref. RFC2453 3.10.1
                    printf("recv %08x > %08x response\n", src_addr, dst_addr);
                    //uint32_t nxthop, if_idx, metric;
                    for (int i = 0; i < rip.numEntries; i++) {
                        /*if (!query(rip.entries[i].addr, &nxthop, &if_idx, &metric) ||
                            ntohl(rip.entries[i].metric) < metric || // 收到的metric 小于自己的 metric
                            nxthop == src_addr) {
                            RoutingTableEntry entry = {
                                    .addr = rip.entries[i].addr & un_mask[maskLength(ntohl(rip.entries[i].mask))],
                                    .len = maskLength(ntohl(rip.entries[i].mask)),
                                    .if_index = (uint32_t) if_index,
                                    .nexthop = src_addr,
                                    .metric = ntohl(rip.entries[i].metric),
                                    .from = if_index
                            };
                            update(true, entry);
                        }
                         */
                        RipEntry &r_entry = rip.entries[i];
                        int metric = ntohl(r_entry.metric) + 1; // 新的metrix为收到的metrix+1
                        uint32_t len = maskLength(ntohl(r_entry.mask));
                        int idx = query_router_entry(r_entry.addr, len);
                        if (idx >= 0) {  // 若查找到则为表项序号，否则为-1
                            RoutingTableEntry &rte = tableEntry[idx]; // 查找到的表项的引用
                            if (rte.nexthop == 0)
                                continue; // 如果是直连路由则直接跳过
                            if (rte.if_index == if_index) {
                                if (metric > 16) {
                                    rte = tableEntry[--p]; // 直接操作数组删除表项
                                } else {
                                    rte.if_index = if_index;
                                    rte.metric = (metric);
                                    rte.nexthop = src_addr;
				    rte.from = if_index;
                                }
                            } else if (metric < (rte.metric)) {
                                rte.if_index = if_index;
                                rte.metric = (metric);
                                rte.nexthop = src_addr;
				rte.from = if_index;
                            }
                            // 没有查到，且metrix小于16，一定是直接插入新的表项
                        } else if (metric <= 16) { // 直接操作数组插入新的表项
                            RoutingTableEntry &rte = tableEntry[p++];
                            rte.addr = r_entry.addr;
                            rte.if_index = if_index;
                            rte.len = len;
                            rte.metric = (metric);
                            rte.nexthop = src_addr;
			    rte.from = if_index;
                        }
                    }
                }
            } else {
                printf("recv %08x > %08x misformed\n", src_addr, dst_addr);
            }
        } else {
            // 3b.1 dst is not me
            // forward
            // beware of endianness
            uint32_t nexthop, dest_if, met;
            if (query(dst_addr, &nexthop, &dest_if, &met) && met < 16) { // 目的地址找到了
                // found
                macaddr_t dest_mac;
                // direct routing
                if (nexthop == 0) {
                    nexthop = dst_addr;
                }
                if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) { // 算出下一跳的dest_mac
                    // found
                    memcpy(output, packet, res);
                    // update ttl and checksum
                    forward(output, res);
                    // TODO: you might want to check ttl=0 case
                    if (output[8]) { // TTL > 0
                        HAL_SendIPPacket(dest_if, output, res, dest_mac);
                    } else { // 构造ICMP time exceeded
                        // time exceeded
                        put_uint8(output, 0, 0x45);
                        put_uint8(output, 8, 0xff);
                        put_uint8(output, 9, 0x01);
                        put_uint32(output, 12, ntohl(addrs[if_index]));
                        put_uint32(output, 16, ntohl(src_addr));
                        put_uint16(output, 10, calculateIPChecksum(output));
                        put_uint8(output, 20, 11);
                        for (int i = 0; i < 20 + 8; i++) {
                            output[20 + i] = packet[i];
                        }
                        uint32_t check = 0;
                        for (int i = 20; i < 56; i += 2) {
                            uint16_t tmp = output[i];
                            tmp = (tmp << 8) + output[i + 1];
                            check += tmp;
                        }
                        while (check >> 16 != 0)
                            check = (check >> 16) + (check & 0xffff);
                        put_uint16(output, 22, (uint16_t) check);
                        HAL_SendIPPacket(if_index, output, 56, src_mac);
                    }
                } else { // 有IP地址但无MAC地址
                    // not found
                    // you can drop it
                    //printf("ARP not found for %x\n", nexthop);
                }
            } else {
                // not found
                // optionally you can send ICMP Host Unreachable
                //printf("IP not found for %x\n", src_addr);
                put_uint8(output, 0, 0x45);
                put_uint8(output, 8, 0xff);
                put_uint8(output, 9, 0x01);
                put_uint32(output, 12, ntohl(addrs[if_index]));
                put_uint32(output, 16, ntohl(src_addr));
                put_uint16(output, 10, calculateIPChecksum(output));
                put_uint8(output, 20, 11);
                for (int i = 0; i < 20 + 8; i++) {
                    output[20 + i] = packet[i];
                }
                uint32_t check = 0;
                for (int i = 20; i < 56; i += 2) {
                    uint16_t tmp = output[i];
                    tmp = (tmp << 8) + output[i + 1];
                    check += tmp;
                }
                while (check >> 16 != 0)
                    check = (check >> 16) + (check & 0xffff);
                put_uint16(output, 22, (uint16_t) check);
                HAL_SendIPPacket(if_index, output, 56, src_mac);
            }
        }
    }
    return 0;
}
