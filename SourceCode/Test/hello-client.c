
#include "stdafx.h"
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#ifndef _WIN32
#include <netinet/in.h>
# ifdef _XOPEN_SOURCE_EXTENDED
#  include <arpa/inet.h>
# endif
#include <sys/socket.h>
#endif

#include <bufferevent.h>
#include <buffer.h>
#include <listener.h>
#include <util.h>
#include <event.h>

static void conn_readcb(struct bufferevent *bev, void *user_data);

int main(int argc, char** argv)
{
    struct event_base* base;
    struct bufferevent* be;
    struct sockaddr_in addr;
#ifdef _WIN32
    WSADATA wsa_data;
    WSAStartup(0x0201, &wsa_data);
#endif

    base = event_base_new();
    if (!base)
    {
        fprintf(stderr, "Could not create!\n");
        return 1;
    }

    if ((be = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS)) == NULL)
    {
        fprintf(stderr, "no socket connected\n");
        return 1;
    }

//    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");//*(unsigned long*)pHost->h_addr_list[0];
    addr.sin_port = htons(9995);

    if (bufferevent_socket_connect(be, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        fprintf(stderr, "connect fail\n");
        getchar();
        return 1;
    }

    bufferevent_setcb(be, conn_readcb, NULL, NULL, NULL);
    bufferevent_enable(be, EV_READ);
    bufferevent_disable(be, EV_WRITE);

    event_base_dispatch(base);

    event_base_free(base);

    printf("done\n");

#ifdef _WIN32
    WSACleanup();
#endif
    getchar();
    return 0;
}

static void
conn_readcb(struct bufferevent *bev, void *user_data)
{
    struct evbuffer *output = bufferevent_get_input(bev);
    struct evbuffer_iovec vec[3];
    int i = 0;
    int len = evbuffer_get_length(output);
    printf("%d message got\n", len);

    for (i = 0; i < 3; ++i)
        vec[i].iov_len = 0;

    evbuffer_peek(output, len, NULL, vec, 3);
    for (i = 0; i < 3; ++i)
    {
        int j;
        if (vec[i].iov_len <= 0) continue;
        for (j = 0; j < vec[i].iov_len; ++j)
            printf("%c", ((char*)vec[i].iov_base)[j]);
        evbuffer_drain(output, vec[i].iov_len);
    }

    if (evbuffer_get_length(output) == 0) {
        printf("flushed answer\n");
        bufferevent_free(bev);
    }
}

