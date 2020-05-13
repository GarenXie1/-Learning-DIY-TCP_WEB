/**
 * 用1500行代码从0开始实现TCP/IP协议栈+WEB服务器
 *
 * 本源码旨在用最简单、最易懂的方式帮助你快速地了解TCP/IP以及HTTP工作原理的主要核心知识点。
 * 所有代码经过精心简化设计，避免使用任何复杂的数据结构和算法，避免实现其它无关紧要的细节。
 *
 * 本源码配套高清的视频教程，免费提供下载！具体的下载网址请见下面。
 * 视频中的PPT不提供下载，但配套了学习指南，请访问下面的网址。
 *
 * 作者：李述铜
 * 网址: http://01ketang.cc/tcpip
 * QQ群：524699753（加群时请注明：tcpip），免费提供关于该源码的支持和问题解答。
 * 微信公众号：请搜索 01课程
 *
 * 版权声明：源码仅供学习参考，请勿用于商业产品，不保证可靠性。二次开发或其它商用前请联系作者。
 * 注：
 * 1.源码不断升级中，该版本可能非最新版。如需获取最新版，请访问上述网址获取最新版本的代码
 * 2.1500行代码指未包含注释的代码。
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
        uint16_t read_size = xtcp_read(tcp, rx_buffer, sizeof(rx_buffer));
        xtcp_write(tcp, rx_buffer, read_size);

    }
    return XNET_ERR_OK;
}

xnet_err_t xserver_http_create(uint16_t port) {
    xnet_err_t err;

    xtcp_t * tcp = xtcp_open(http_handler);
    if (!tcp) return XNET_ERR_MEM;
    err = xtcp_bind(tcp, port);       // HTTP熟知端口
    if (err < 0) return  err;

    return xtcp_listen(tcp);
}
