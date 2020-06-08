/**
 * ��1500�д����0��ʼʵ��TCP/IPЭ��ջ+WEB������
 *
 * ��Դ��ּ������򵥡����׶��ķ�ʽ��������ٵ��˽�TCP/IP�Լ�HTTP����ԭ�����Ҫ����֪ʶ�㡣
 * ���д��뾭�����ļ���ƣ�����ʹ���κθ��ӵ����ݽṹ���㷨������ʵ�������޹ؽ�Ҫ��ϸ�ڡ�
 *
 * ��Դ�����׸������Ƶ�̳̣�����ṩ���أ������������ַ������档
 * ��Ƶ�е�PPT��ʱ�ṩ���أ���������ѧϰָ�ϣ�������������ַ��
 *
 * ���ߣ�����ͭ
 * ��ַ: http://01ketang.cc/tcpip
 * QQȺ��524699753����Ⱥʱ��ע����tcpip��������ṩ���ڸ�Դ���֧�ֺ�������
 * ΢�Ź��ںţ������� 01�γ�
 *
 * ��Ȩ������Դ�����ѧϰ�ο�������������ҵ��Ʒ������֤�ɿ��ԡ����ο�������������ǰ����ϵ���ߡ�
 * ע��
 * 1.Դ�벻�������У��ð汾���ܷ����°档�����ȡ���°棬�����������ַ��ȡ���°汾�Ĵ���
 * 2.1500�д���ָδ����ע�͵Ĵ��롣
 *
 * �������ѧϰ���γ�֮�󣬶������о�TCP/IP����Ȥ����ӭ��ע�ҵĺ����γ̡��ҽ�������һ�׸�������
 * ���TCP/IP�Ŀγ̡����ö��̵߳ķ�ʽ��ʵ�ָ����ƵĹ��ܣ�������������
 * 1. IP��ķ�Ƭ������
 * 2. Ping���ܵ�ʵ��
 * 3. TCP���������Ƶ�
 * 4. ����UDP��TFTP������ʵ��
 * 5. DNS�����Ӵ�
 * 6. DHCP��̬��ַ��ȡ
 * 7. HTTP������
 * ..... ���๦�ܿ�����...........
 * ���������Ȥ�Ļ�����ӭ��ע��
 */
#include "xserver_http.h"
#include <string.h>
#include <stdio.h>

static xnet_err_t http_handler (xtcp_t* tcp, xtcp_conn_state_t state) {
    if (state == XTCP_CONN_CONNECTED) {
        printf("http conntected.\n");
    } else if (state == XTCP_CONN_CLOSED) {
        printf("http closed.\n");
    }
    return XNET_ERR_OK;
}

xnet_err_t xserver_http_create(uint16_t port) {
    xnet_err_t err;

    xtcp_t * tcp = xtcp_open(http_handler);
    if (!tcp) return XNET_ERR_MEM;
    err = xtcp_bind(tcp, port);       // HTTP��֪�˿�
    if (err < 0) return  err;

    return xtcp_listen(tcp);
}
