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
 * 网址: http://01ketang.cc/xnet-tiny
 * 本课程还将配套相应的学习指南资料，请访问课程网站找到。
 * QQ群：524699753（加群时请注明：tcpip），免费提供关于该源码的支持和问题解答。
 * 如群满，可在上述网址中找到新的群。
 * 微信公众号：请搜索 01课程
 *
 * 版权声明：源码仅供学习参考，请勿用于商业产品，不保证可靠性。二次开发或其它商用前请联系作者。
 * 注：
 * 1.源码不断升级中，该版本可能非最新版。如需获取最新版，请访问上述网址获取最新版本的代码
 * 2.1500行代码指未包含注释的代码。
 */
#ifndef XSERVER_HTTP_H
#define XSERVER_HTTP_H

#include "xnet_tiny.h"

#if defined(__APPLE__)      // 根据实际情况修改
#define XHTTP_DOC_DIR               "/Users/mac/work/git/xnet-tiny/htdocs"  // html文档所在的目录
#else
#define XHTTP_DOC_DIR               "d:/tiny_net"  // html文档所在的目录
#endif

xnet_err_t xserver_http_create(uint16_t port);
void xserver_http_run(void);

#endif // XSERVER_HTTP_H
