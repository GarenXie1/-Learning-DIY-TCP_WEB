﻿/**
 * 用1500行代码从0开始实现TCP/IP协议栈+WEB服务器
 *
 * 本源码旨在用最简单、最易懂的方式帮助你快速地了解TCP/IP以及HTTP工作原理的主要核心知识点。
 * 所有代码经过精心简化设计，避免使用任何复杂的数据结构和算法，避免实现其它无关紧要的细节。
 *
 * 作者：李述铜
 * 微信公众号：01课堂
 * 网址：https://www.yuque.com/lishutong-docs
 *
 * 版权声明：源码仅供学习参考，请勿用于商业产品，不保证可靠性。二次开发或其它商用前请联系作者。
 *
 * 注意：本课程提供的tcp/ip实现很简单，只能够用于演示基本的协议运行机制。我还开发了另一套更加完整的课程，
 * 展示了一个更加完成的TCP/IP协议栈的实现。功能包括：
 * 1. IP层的分片与重组
 * 2. Ping功能的实现
 * 3. TCP的流量控制等
 * 4. 基于UDP的TFTP服务器实现
 * 5. DNS域名接触
 * 6. HTTP服务器
 * 7. 提供socket接口供应用程序使用
 * 8、代码可移植，可移植到arm和x86平台上
 * ..... 更多功能开发中...........
 * 如果你有兴趣的话，请扫仓库中的二维码，或者点击以上面的链接可找到该课程。
 */
#include "xserver_http.h"
#include <string.h>
#include <stdio.h>

static uint8_t rx_buffer[1024];

static xnet_err_t http_handler (xtcp_t* tcp, xtcp_conn_state_t state) {
    if (state == XTCP_CONN_CONNECTED) {
        printf("http conntected.\n");
    } else if (state == XTCP_CONN_CLOSED) {
        printf("http closed.\n");
    } else if (state == XTCP_CONN_DATA_RECV) {
        uint8_t* data = tx_buffer;

        uint16_t read_size = xtcp_read(tcp, tx_buffer, sizeof(tx_buffer));
        while (read_size) {
            uint16_t curr_size = xtcp_write(tcp, data, read_size);
            data += curr_size;
            read_size -= curr_size;
        }
    }
    return XNET_ERR_OK;
}

xnet_err_t xserver_http_create(uint16_t port) {
    xtcp_t * tcp = xtcp_open(http_handler);
    xtcp_bind(tcp, port);
    xtcp_listen(tcp);
    return XNET_ERR_OK;
}
