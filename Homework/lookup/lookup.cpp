#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>

/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

RoutingTableEntry tableEntry[100];
int p = 0;  // 表尾+1
uint32_t un_mask[33] = {0x00000000,
                        0x80000000, 0xC0000000, 0xE0000000, 0xF0000000,
                        0xF8000000, 0xFC000000, 0xFE000000, 0xFF000000,
                        0xFF800000, 0xFFC00000, 0xFFE00000, 0xFFF00000,
                        0xFFF80000, 0xFFFC0000, 0xFFFE0000, 0xFFFF0000,
                        0xFFFF8000, 0xFFFFC000, 0xFFFFE000, 0xFFFFF000,
                        0xFFFFF800, 0xFFFFFC00, 0xFFFFFE00, 0xFFFFFF00,
                        0xFFFFFF80, 0xFFFFFFC0, 0xFFFFFFE0, 0xFFFFFFF0,
                        0xFFFFFFF8, 0xFFFFFFFC, 0xFFFFFFFE, 0xFFFFFFFF};

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 * 
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len 匹配。
 */
void update(bool insert, RoutingTableEntry entry) {
    entry.addr = ntohl(entry.addr);
    if (insert) {
        for (int i = 0; i < p; i++) {
            if (tableEntry[i].addr == entry.addr && tableEntry[i].len == entry.len) {
                tableEntry[i] = entry;
                return;
            }
        }
        tableEntry[p++] = entry;
    } else {
        for (int i = 0; i < p; i++)
            if (tableEntry[i].addr == entry.addr && tableEntry[i].len == entry.len)
                tableEntry[i] = tableEntry[--p];
    }
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
    addr = ntohl(addr);
    uint32_t max_len = 0, ans = 0xFFFFFFFF;
    for (int i = 0; i < p; i++) {
        if (tableEntry[i].len > max_len && (tableEntry[i].addr == (addr & un_mask[tableEntry[i].len]))) {
            max_len = tableEntry[i].len;
            ans = i;
        }
    }
    if (~ans) {
        *if_index = tableEntry[ans].if_index;
        *nexthop = tableEntry[ans].nexthop;
        return true;
    }
    *nexthop = 0;
    *if_index = 0;
    return false;
}
