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
 */

/*
 * A user-space link to the usbnet remotes (Harmony 900/1000/1100).
 *
 * These remotes are USB CDC MDLM devices using Belcarra's BLAN protocol:
 * every bulk transfer is one Ethernet frame followed by a CRC32. Rather than
 * depending on an OS driver for that (Linux's zaurus module plus a DHCP
 * server, Logitech's driver on Windows, nothing at all on macOS), this talks
 * to the remote directly with libusb and carries the little networking the
 * remote needs - ARP, its DHCP request, and TCP - in-process. No driver, no
 * network configuration and no root are involved.
 */

#ifndef USBNET_LINK_H
#define USBNET_LINK_H

#include <stdint.h>

/*
 * Find the remote, claim it and wait until it has its address. Returns 0, or
 * LC_ERROR_CONNECT when no usbnet remote is attached (or it never comes up).
 */
int UsbNetLink_Open(unsigned int timeout_ms);
void UsbNetLink_Close(void);

/* Returns a connection handle (>= 0), or a negative LC_ERROR_* code. */
int UsbNetLink_Connect(uint16_t port, unsigned int timeout_ms);
int UsbNetLink_Send(int conn, const uint8_t *data, unsigned int len);
/*
 * Waits up to timeout_ms for data. On return len holds the number of bytes
 * read; 0 means the remote closed the connection.
 */
int UsbNetLink_Recv(int conn, uint8_t *data, unsigned int &len,
                    unsigned int timeout_ms);
void UsbNetLink_Disconnect(int conn);

#endif
