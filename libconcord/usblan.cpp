/*
 * vim:tw=80:ai:tabstop=4:softtabstop=4:shiftwidth=4:expandtab
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright Kevin Timmerman 2007
 * (C) Copyright Kevin Timmerman 2008
 */

#include "usblan.h"

#include <string.h>
#include <errno.h>
#include <fcntl.h>

#ifdef _WIN32
#include <winsock.h>
#else
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#define closesocket close
#define SOCKET int
#define SOCKET_ERROR -1
#define INVALID_SOCKET -1
#endif

#ifdef __FreeBSD__
#include <netinet/in.h>
#endif

#include "libconcord.h"
#include "lc_internal.h"

#ifdef HAVE_USBNET_LINK
#include "usbnet_link.h"
#endif

/*
 * Two ways to reach a usbnet remote. The direct USB link (usbnet_link.cpp)
 * needs no OS driver and is tried first; the socket path relies on an OS
 * network interface to the remote (Logitech's driver on Windows, or zaurus
 * and a DHCP server on Linux) and is used when the link cannot claim it.
 */
enum UsbLanTransport { TRANSPORT_NONE, TRANSPORT_SOCKET, TRANSPORT_LINK };
static UsbLanTransport transport = TRANSPORT_NONE;
static int link_conn = -1;

static SOCKET sock = INVALID_SOCKET;

const char * const remote_ip_address = "169.254.1.2";
const uint16_t remote_port = 3074;
const int connect_timeout = 1; // try to connect for 1 seconds

const char * const http_get_cmd = "\
GET /xmluserrfsetting HTTP/1.1\r\n\
User-Agent: Jakarta Commons-HttpClient/3.1\r\n\
Host: 169.254.1.2\r\n\
\r\n";

int InitializeUsbLan(void)
{
    return 0;
}

int ShutdownUsbLan(void)
{
    int err=0;

#ifdef HAVE_USBNET_LINK
    if (transport == TRANSPORT_LINK) {
        UsbNetLink_Disconnect(link_conn);
        link_conn = -1;
        UsbNetLink_Close();
    }
#endif
    transport = TRANSPORT_NONE;

    // Close the socket
    if (sock != INVALID_SOCKET) {
        err = closesocket(sock);
        sock = INVALID_SOCKET;
        if (err) {
            report_net_error("closesocket()");
            return LC_ERROR_OS_NET;
        }
    }

    return 0;
}

#ifdef HAVE_USBNET_LINK
/* How long a remote that has just been plugged in or reset may take. */
static const unsigned int link_open_timeout_ms = 15000;
static const unsigned int link_connect_timeout_ms = 5000;
static const unsigned int link_recv_timeout_ms = 30000;

static int FindUsbLanRemoteOverUsb(void)
{
    int err = UsbNetLink_Open(link_open_timeout_ms);
    if (err)
        return err;
    link_conn = UsbNetLink_Connect(remote_port, link_connect_timeout_ms);
    if (link_conn < 0) {
        err = -link_conn;
        link_conn = -1;
        UsbNetLink_Close();
        return err;
    }
    debug("Connected to the remote over USB!");
    return 0;
}
#endif

static int FindUsbLanRemoteOverSocket(void);

int FindUsbLanRemote(void)
{
    ShutdownUsbLan();
#ifdef HAVE_USBNET_LINK
    if (FindUsbLanRemoteOverUsb() == 0) {
        transport = TRANSPORT_LINK;
        return 0;
    }
#endif
    int err = FindUsbLanRemoteOverSocket();
    if (err == 0)
        transport = TRANSPORT_SOCKET;
    return err;
}

static int FindUsbLanRemoteOverSocket(void)
{
    int err;

    hostent* addr = gethostbyname(remote_ip_address);

    if (!addr) {
        report_net_error("gethostbyname()");
        return LC_ERROR_OS_NET;
    }

    sockaddr_in sa;
    memcpy(&(sa.sin_addr), addr->h_addr, addr->h_length);
    sa.sin_family = AF_INET;        // TCP/IP
    sa.sin_port = htons(remote_port);    // Port 3074

    sock = socket(sa.sin_family, SOCK_STREAM, 0);    // TCP
    //sock = socket(sa.sin_family, SOCK_DGRAM, 0);    // UDP

    // Make the socket non-blocking so it doesn't hang on systems that 
    // don't have a usbnet remote.
    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(sock, &wset);
    struct timeval tv;
    tv.tv_sec = connect_timeout;
    tv.tv_usec = 0;
#ifdef _WIN32
    u_long non_blocking = 1;
    if(ioctlsocket(sock, FIONBIO, &non_blocking) != 0) {
        report_net_error("ioctlsocket()");
        return LC_ERROR_OS_NET;
    }
#else
    int flags = 0;
    if((flags = fcntl(sock, F_GETFL, 0)) < 0) {
        report_net_error("fcntl()");
        return LC_ERROR_OS_NET;
    }
    if(fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        report_net_error("fcntl()");
        return LC_ERROR_OS_NET;
    }
#endif

    if ((err = connect(sock,(struct sockaddr*)&sa,sizeof(sa)))) {
#ifdef _WIN32
        if (WSAGetLastError() != WSAEWOULDBLOCK) {
#else
        if (errno != EINPROGRESS) {
#endif
            report_net_error("connect()");
            return LC_ERROR_OS_NET;
        }
    }

    if ((err = select(sock+1, NULL, &wset, NULL, &tv)) <= 0) {
        report_net_error("select()");
        return LC_ERROR_OS_NET;
    }

    // Change the socket back to blocking which should be fine now that we
    // connected.
#ifdef _WIN32
    non_blocking = 0;
    if(ioctlsocket(sock, FIONBIO, &non_blocking) != 0) {
        report_net_error("ioctlsocket()");
        return LC_ERROR_OS_NET;
    }
#else
    if((flags = fcntl(sock, F_GETFL, 0)) < 0) {
        report_net_error("fcntl()");
        return LC_ERROR_OS_NET;
    }
    if(fcntl(sock, F_SETFL, flags & ~O_NONBLOCK) < 0) {
        report_net_error("fcntl()");
        return LC_ERROR_OS_NET;
    }
#endif

    debug("Connected to USB LAN driver!");

    return 0;
}

int UsbLan_Write(unsigned int len, uint8_t *data)
{
#ifdef HAVE_USBNET_LINK
    if (transport == TRANSPORT_LINK) {
        int err = UsbNetLink_Send(link_conn, data, len);
        if (err)
            return err;
        debug("%i bytes sent", len);
        return 0;
    }
#endif
    int err = send(sock, reinterpret_cast<char*>(data), len, 0);

    if (err == SOCKET_ERROR) {
        report_net_error("send()");
        return LC_ERROR_OS_NET;
    }

    debug("%i bytes sent", err);

    return 0;
}


int UsbLan_Read(unsigned int &len, uint8_t *data)
{
#ifdef HAVE_USBNET_LINK
    if (transport == TRANSPORT_LINK) {
        int err = UsbNetLink_Recv(link_conn, data, len, link_recv_timeout_ms);
        if (err) {
            len = 0;
            return err;
        }
        debug("%i bytes received", len);
        return 0;
    }
#endif
    int err = recv(sock, reinterpret_cast<char*>(data), len, 0);

    if (err == SOCKET_ERROR) {
        report_net_error("recv()");
        len = 0;
        return LC_ERROR_OS_NET;
    } 

    len = static_cast<unsigned int>(err);
    debug("%i bytes received", len);

    return 0;
}

/* The body of an HTTP response, as a new string. */
static int HttpBody(char *response, char **data)
{
    char *body = strstr(response, "\r\n\r\n"); // end of the http header
    if (body == NULL) {
        report_net_error("strstr()");
        return LC_ERROR_OS_NET;
    }
    body += 4;
    *data = new char[strlen(body)+1];
    strncpy(*data, body, strlen(body)+1);
    return 0;
}

#ifdef HAVE_USBNET_LINK
static int GetXMLUserRFSettingOverUsb(char **data)
{
    char buf[4096];
    int conn = UsbNetLink_Connect(80, link_connect_timeout_ms);
    if (conn < 0)
        return -conn;
    debug("Connected to the remote's web server over USB!");

    int err = UsbNetLink_Send(conn, reinterpret_cast<const uint8_t*>(
        http_get_cmd), strlen(http_get_cmd));
    unsigned int len = 0;
    while (!err && len < sizeof(buf) - 1) {
        unsigned int got = sizeof(buf) - 1 - len;
        err = UsbNetLink_Recv(conn, reinterpret_cast<uint8_t*>(buf + len),
                              got, link_recv_timeout_ms);
        if (err || got == 0)      // 0: the server closed the connection
            break;
        len += got;
    }
    UsbNetLink_Disconnect(conn);
    if (err)
        return err;
    buf[len] = '\0';
    return HttpBody(buf, data);
}
#endif

int GetXMLUserRFSetting(char **data)
{
    int err;
    int web_sock;
    char buf[4096];

#ifdef HAVE_USBNET_LINK
    if (transport == TRANSPORT_LINK)
        return GetXMLUserRFSettingOverUsb(data);
#endif

    hostent* addr = gethostbyname(remote_ip_address);

    if (!addr) {
        report_net_error("gethostbyname()");
        return LC_ERROR_OS_NET;
    }

    sockaddr_in sa;
    memcpy(&(sa.sin_addr), addr->h_addr, addr->h_length);
    sa.sin_family = AF_INET;        // TCP/IP
    sa.sin_port = htons(80);                // Web Server port

    web_sock = socket(sa.sin_family, SOCK_STREAM, 0);    // TCP

    if ((err = connect(web_sock,(struct sockaddr*)&sa,sizeof(sa)))) {
        report_net_error("connect()");
        closesocket(web_sock);
        return LC_ERROR_OS_NET;
    }
    debug("Connected to USB LAN web server!");

    err = send(web_sock, http_get_cmd, strlen(http_get_cmd), 0);
    if (err == SOCKET_ERROR) {
        report_net_error("send()");
        closesocket(web_sock);
        return LC_ERROR_OS_NET;
    }
    debug("%i bytes sent", err);

    unsigned int len = 0;
    char* buf_ptr = buf;
    do {
        // One byte is kept for the terminator.
        err = recv(web_sock, buf_ptr, sizeof(buf)-1-len, 0);
        if (err == SOCKET_ERROR) {
            report_net_error("recv()");
            closesocket(web_sock);
            return LC_ERROR_OS_NET;
        }
        len += err;
        buf_ptr += err;
        debug("%i bytes received", err);
    } while (err > 0 && len < sizeof(buf)-1); // recv returns 0 at the end
    closesocket(web_sock);
    buf[len] = '\0';

    return HttpBody(buf, data);
}
