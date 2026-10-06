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
 * User-space BLAN link for the usbnet remotes. See usbnet_link.h.
 *
 * What the remote does, as observed on a Harmony 900:
 *  - one interface, CDC class 2 / MDLM subclass 0x0A, with the BLAN GUID and
 *    the CRC flag in its MDLM detail descriptor, a bulk IN, a bulk OUT and
 *    an interrupt IN endpoint;
 *  - each bulk transfer carries one Ethernet frame plus a little-endian
 *    CRC32 of it;
 *  - once enumerated it broadcasts DHCP DISCOVERs until somebody gives it an
 *    address, and expects to be 169.254.1.2 - the address libconcord has
 *    always connected to. A remote that still holds an earlier lease skips
 *    DHCP and simply answers at that address;
 *  - it listens for TCP on 3074 (the protocol) and 80 (a small web server).
 *
 * The TCP here is deliberately small: one peer, a reliable point-to-point
 * link, a handful of connections. Segments that arrive out of order are
 * dropped and re-acknowledged, and anything unacknowledged is resent from
 * the oldest unacknowledged byte.
 */

#include "usbnet_link.h"

#include <libusb.h>
#include <string.h>
#include <time.h>
#include <vector>

#include "libconcord.h"
#include "lc_internal.h"

namespace {

const uint16_t VENDOR_LOGITECH = 0x046D;
const uint16_t PRODUCT_USBNET = 0xC11F;   // 900, 1000, 1100

const uint8_t HOST_MAC[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
const uint8_t BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const uint8_t HOST_IP[4] = {169, 254, 1, 1};
const uint8_t REMOTE_IP[4] = {169, 254, 1, 2};
const uint8_t NETMASK[4] = {255, 255, 255, 0};
const uint8_t BROADCAST_IP[4] = {255, 255, 255, 255};

const uint16_t ETH_IP = 0x0800;
const uint16_t ETH_ARP = 0x0806;
const uint8_t PROTO_ICMP = 1;
const uint8_t PROTO_TCP = 6;
const uint8_t PROTO_UDP = 17;

const uint8_t TCP_FIN = 0x01;
const uint8_t TCP_SYN = 0x02;
const uint8_t TCP_RST = 0x04;
const uint8_t TCP_PSH = 0x08;
const uint8_t TCP_ACK = 0x10;

const unsigned int MAX_FRAME = 2048;
const unsigned int RX_WINDOW = 65535;
const unsigned int MAX_CONNECTIONS = 4;
const unsigned int POLL_MS = 20;
const unsigned int RTO_MIN_MS = 250;
const unsigned int RTO_MAX_MS = 2000;
const unsigned int MAX_RETRANSMITS = 10;

enum TcpState { TCP_CLOSED, TCP_SYN_SENT, TCP_OPEN, TCP_PEER_CLOSED };

struct Connection {
    bool used;
    TcpState state;
    uint16_t local_port;
    uint16_t remote_port;
    uint32_t snd_una;            // oldest unacknowledged sequence number
    uint32_t snd_nxt;
    uint32_t rcv_nxt;
    uint16_t peer_window;
    uint16_t mss;
    std::vector<uint8_t> unacked; // bytes from snd_una onwards
    std::vector<uint8_t> received;
    unsigned long sent_at;        // ms, when the oldest unacked byte was sent
    unsigned int rto;
    unsigned int retransmits;
};

struct Link {
    libusb_context *ctx;
    libusb_device_handle *dev;
    int interface;
    uint8_t ep_in;
    uint8_t ep_out;
    uint16_t out_packet_size;
    bool gone;                    // the remote went away (unplugged, reset)
    bool addressed;               // the remote has 169.254.1.2
    bool remote_mac_known;
    uint8_t remote_mac[6];
    uint16_t ip_id;
    uint16_t next_port;
    Connection conn[MAX_CONNECTIONS];
};

Link link;

unsigned long now_ms()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000UL + ts.tv_nsec / 1000000UL;
}

/* sequence-number comparison, modulo 2^32 */
bool seq_lt(uint32_t a, uint32_t b) { return (int32_t)(a - b) < 0; }
bool seq_le(uint32_t a, uint32_t b) { return (int32_t)(a - b) <= 0; }

void put16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xFF; }
void put32(uint8_t *p, uint32_t v)
{
    p[0] = v >> 24; p[1] = (v >> 16) & 0xFF; p[2] = (v >> 8) & 0xFF;
    p[3] = v & 0xFF;
}
uint16_t get16(const uint8_t *p) { return (p[0] << 8) | p[1]; }
uint32_t get32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | (p[2] << 8) | p[3];
}

uint32_t crc32(const uint8_t *data, unsigned int len)
{
    static uint32_t table[256];
    static bool ready = false;
    if (!ready) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++)
                c = (c & 1) ? 0xEDB88320 ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
        ready = true;
    }
    uint32_t crc = 0xFFFFFFFF;
    for (unsigned int i = 0; i < len; i++)
        crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFF;
}

/* The Internet checksum, over a pseudo-header sum carried in from the caller. */
uint16_t checksum(const uint8_t *data, unsigned int len, uint32_t sum = 0)
{
    for (unsigned int i = 0; i + 1 < len; i += 2)
        sum += get16(data + i);
    if (len & 1)
        sum += data[len - 1] << 8;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum & 0xFFFF;
}

uint32_t pseudo_sum(const uint8_t *src, const uint8_t *dst, uint8_t proto,
                    unsigned int len)
{
    return get16(src) + get16(src + 2) + get16(dst) + get16(dst + 2) + proto
        + len;
}

/* Frames */

int send_frame(const uint8_t *dst_mac, uint16_t ethertype,
               const uint8_t *payload, unsigned int len)
{
    if (link.gone)
        return LC_ERROR_OS_NET;
    uint8_t frame[MAX_FRAME];
    if (14 + len + 5 > sizeof(frame))
        return LC_ERROR;
    memcpy(frame, dst_mac, 6);
    memcpy(frame + 6, HOST_MAC, 6);
    put16(frame + 12, ethertype);
    memcpy(frame + 14, payload, len);
    unsigned int n = 14 + len;
    const uint32_t crc = crc32(frame, n);
    frame[n++] = crc & 0xFF;
    frame[n++] = (crc >> 8) & 0xFF;
    frame[n++] = (crc >> 16) & 0xFF;
    frame[n++] = crc >> 24;
    // A transfer that ends on a packet boundary would need a zero-length
    // packet to end it; a pad byte after the CRC avoids the question.
    if (n % link.out_packet_size == 0)
        frame[n++] = 0;

    int sent = 0;
    int err = libusb_bulk_transfer(link.dev, link.ep_out, frame, n, &sent,
                                   1000);
    if (err == LIBUSB_ERROR_NO_DEVICE || err == LIBUSB_ERROR_IO) {
        link.gone = true;
    }
    if (err) {
        debug("bulk out failed: %s", libusb_error_name(err));
        return LC_ERROR_OS_NET;
    }
    return 0;
}

int send_ip(uint8_t proto, const uint8_t *dst_ip, const uint8_t *dst_mac,
            const uint8_t *payload, unsigned int len)
{
    uint8_t packet[MAX_FRAME];
    if (20 + len > 1500)
        return LC_ERROR;
    packet[0] = 0x45;
    packet[1] = 0;
    put16(packet + 2, 20 + len);
    put16(packet + 4, link.ip_id++);
    put16(packet + 6, 0x4000);    // don't fragment
    packet[8] = 64;
    packet[9] = proto;
    put16(packet + 10, 0);
    memcpy(packet + 12, HOST_IP, 4);
    memcpy(packet + 16, dst_ip, 4);
    put16(packet + 10, checksum(packet, 20));
    memcpy(packet + 20, payload, len);
    return send_frame(dst_mac, ETH_IP, packet, 20 + len);
}

int send_udp(uint16_t sport, uint16_t dport, const uint8_t *dst_ip,
             const uint8_t *dst_mac, const uint8_t *payload, unsigned int len)
{
    uint8_t datagram[MAX_FRAME];
    put16(datagram, sport);
    put16(datagram + 2, dport);
    put16(datagram + 4, 8 + len);
    put16(datagram + 6, 0);
    memcpy(datagram + 8, payload, len);
    uint16_t sum = checksum(datagram, 8 + len,
                            pseudo_sum(HOST_IP, dst_ip, PROTO_UDP, 8 + len));
    put16(datagram + 6, sum ? sum : 0xFFFF);
    return send_ip(PROTO_UDP, dst_ip, dst_mac, datagram, 8 + len);
}

/* ARP */

void send_arp(uint16_t op, const uint8_t *target_mac, const uint8_t *target_ip,
              const uint8_t *dst_mac)
{
    uint8_t arp[28];
    put16(arp, 1);                // Ethernet
    put16(arp + 2, ETH_IP);
    arp[4] = 6;
    arp[5] = 4;
    put16(arp + 6, op);
    memcpy(arp + 8, HOST_MAC, 6);
    memcpy(arp + 14, HOST_IP, 4);
    memcpy(arp + 18, target_mac, 6);
    memcpy(arp + 24, target_ip, 4);
    send_frame(dst_mac, ETH_ARP, arp, sizeof(arp));
}

void learn_remote(const uint8_t *mac)
{
    if (!link.remote_mac_known || memcmp(link.remote_mac, mac, 6)) {
        memcpy(link.remote_mac, mac, 6);
        link.remote_mac_known = true;
        debug("remote is %02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1],
              mac[2], mac[3], mac[4], mac[5]);
    }
}

void handle_arp(const uint8_t *arp, unsigned int len)
{
    if (len < 28 || get16(arp + 2) != ETH_IP)
        return;
    const uint16_t op = get16(arp + 6);
    const uint8_t *sha = arp + 8, *spa = arp + 14, *tpa = arp + 24;
    if (!memcmp(spa, REMOTE_IP, 4)) {
        learn_remote(sha);
        link.addressed = true;
    }
    if (op == 1 && !memcmp(tpa, HOST_IP, 4))
        send_arp(2, sha, spa, sha);
}

/* DHCP: the remote asks for an address; it gets 169.254.1.2. */

void handle_dhcp(const uint8_t *msg, unsigned int len)
{
    if (len < 240 || msg[0] != 1)
        return;
    int type = 0;
    for (unsigned int i = 240; i < len && msg[i] != 255;) {
        if (msg[i] == 0) {
            i++;
            continue;
        }
        if (i + 1 >= len)
            break;
        if (msg[i] == 53 && msg[i + 1] >= 1 && i + 2 < len)
            type = msg[i + 2];
        i += 2 + msg[i + 1];
    }
    if (type != 1 && type != 3)   // DISCOVER, REQUEST
        return;
    learn_remote(msg + 28);

    uint8_t reply[300];
    memset(reply, 0, sizeof(reply));
    reply[0] = 2;                 // BOOTREPLY
    reply[1] = 1;
    reply[2] = 6;
    memcpy(reply + 4, msg + 4, 4);    // xid
    memcpy(reply + 10, msg + 10, 2);  // flags
    memcpy(reply + 16, REMOTE_IP, 4); // yiaddr
    memcpy(reply + 20, HOST_IP, 4);   // siaddr
    memcpy(reply + 28, msg + 28, 16); // chaddr
    uint8_t *o = reply + 236;
    *o++ = 0x63; *o++ = 0x82; *o++ = 0x53; *o++ = 0x63;
    *o++ = 53; *o++ = 1; *o++ = (type == 1) ? 2 : 5;   // OFFER / ACK
    *o++ = 54; *o++ = 4; memcpy(o, HOST_IP, 4); o += 4;
    *o++ = 51; *o++ = 4; put32(o, 86400); o += 4;
    *o++ = 1; *o++ = 4; memcpy(o, NETMASK, 4); o += 4;
    *o++ = 3; *o++ = 4; memcpy(o, HOST_IP, 4); o += 4;
    *o++ = 255;
    send_udp(67, 68, BROADCAST_IP, BROADCAST_MAC, reply, o - reply);
    if (type == 3) {
        link.addressed = true;
        debug("remote leased 169.254.1.2");
    }
}

/* TCP */

void send_segment(Connection &c, uint32_t seq, uint8_t flags,
                  const uint8_t *data, unsigned int len)
{
    uint8_t seg[1600];
    const unsigned int hlen = (flags & TCP_SYN) ? 24 : 20;
    put16(seg, c.local_port);
    put16(seg + 2, c.remote_port);
    put32(seg + 4, seq);
    put32(seg + 8, (flags & TCP_ACK) ? c.rcv_nxt : 0);
    seg[12] = (hlen / 4) << 4;
    seg[13] = flags;
    const unsigned int window = c.received.size() < RX_WINDOW
        ? RX_WINDOW - c.received.size() : 0;
    put16(seg + 14, window);
    put16(seg + 16, 0);
    put16(seg + 18, 0);
    if (hlen == 24) {
        seg[20] = 2;              // MSS option
        seg[21] = 4;
        put16(seg + 22, 1460);
    }
    if (len)
        memcpy(seg + hlen, data, len);
    put16(seg + 16, checksum(seg, hlen + len,
                             pseudo_sum(HOST_IP, REMOTE_IP, PROTO_TCP,
                                        hlen + len)));
    send_ip(PROTO_TCP, REMOTE_IP, link.remote_mac, seg, hlen + len);
}

void send_ack(Connection &c)
{
    send_segment(c, c.snd_nxt, TCP_ACK, NULL, 0);
}

/* Send whatever unacknowledged data fits in the peer's window, from `from`. */
void transmit(Connection &c, uint32_t from)
{
    const uint32_t limit = c.snd_una + (c.peer_window ? c.peer_window : 1);
    uint32_t seq = from;
    while (seq_lt(seq, c.snd_una + c.unacked.size()) && seq_lt(seq, limit)) {
        unsigned int offset = seq - c.snd_una;
        unsigned int n = c.unacked.size() - offset;
        if (n > c.mss)
            n = c.mss;
        if (n > limit - seq)
            n = limit - seq;
        send_segment(c, seq, TCP_ACK | TCP_PSH, &c.unacked[offset], n);
        seq += n;
    }
    if (seq_lt(c.snd_nxt, seq))
        c.snd_nxt = seq;
    c.sent_at = now_ms();
}

void handle_tcp(const uint8_t *seg, unsigned int len)
{
    if (len < 20)
        return;
    const uint16_t sport = get16(seg), dport = get16(seg + 2);
    const uint32_t seq = get32(seg + 4), ack = get32(seg + 8);
    const unsigned int hlen = (seg[12] >> 4) * 4;
    const uint8_t flags = seg[13];
    if (hlen < 20 || hlen > len)
        return;
    const uint8_t *data = seg + hlen;
    unsigned int dlen = len - hlen;

    Connection *cp = NULL;
    for (unsigned int i = 0; i < MAX_CONNECTIONS; i++) {
        if (link.conn[i].used && link.conn[i].local_port == dport
            && link.conn[i].remote_port == sport) {
            cp = &link.conn[i];
        }
    }
    if (!cp)
        return;
    Connection &c = *cp;

    if (flags & TCP_RST) {
        debug("connection to port %u reset by the remote", c.remote_port);
        c.state = TCP_CLOSED;
        return;
    }
    if (c.state == TCP_SYN_SENT) {
        if ((flags & (TCP_SYN | TCP_ACK)) != (TCP_SYN | TCP_ACK)
            || ack != c.snd_una + 1)
            return;
        c.snd_una = c.snd_nxt = ack;
        c.rcv_nxt = seq + 1;
        c.peer_window = get16(seg + 14);
        for (unsigned int i = 20; i + 1 < hlen;) {
            if (seg[i] == 0)
                break;
            if (seg[i] == 1) {
                i++;
                continue;
            }
            if (seg[i] == 2 && seg[i + 1] == 4 && i + 3 < hlen)
                c.mss = get16(seg + i + 2) < 1460 ? get16(seg + i + 2) : 1460;
            if (seg[i + 1] < 2)
                break;
            i += seg[i + 1];
        }
        c.state = TCP_OPEN;
        send_ack(c);
        return;
    }

    if (flags & TCP_ACK) {
        c.peer_window = get16(seg + 14);
        // snd_nxt may run one past the data: our FIN takes a sequence number.
        if (seq_lt(c.snd_una, ack) && seq_le(ack, c.snd_nxt)) {
            const uint32_t acked = ack - c.snd_una;
            c.unacked.erase(c.unacked.begin(), c.unacked.begin()
                            + (acked < c.unacked.size() ? acked
                               : c.unacked.size()));
            c.snd_una = ack;
            c.rto = RTO_MIN_MS;
            c.retransmits = 0;
            c.sent_at = now_ms();
        }
    }

    bool acknowledge = false;
    if (dlen) {
        if (seq_lt(seq, c.rcv_nxt)) {          // partly or wholly a repeat
            const uint32_t skip = c.rcv_nxt - seq;
            if (skip >= dlen) {
                dlen = 0;
            } else {
                data += skip;
                dlen -= skip;
            }
            acknowledge = true;
        } else if (seq != c.rcv_nxt) {         // a gap: ask for it again
            dlen = 0;
            acknowledge = true;
        }
        if (dlen) {
            c.received.insert(c.received.end(), data, data + dlen);
            c.rcv_nxt += dlen;
            acknowledge = true;
        }
    }
    if ((flags & TCP_FIN) && seq + (len - hlen) == c.rcv_nxt
        && c.state == TCP_OPEN) {
        c.rcv_nxt += 1;
        c.state = TCP_PEER_CLOSED;
        acknowledge = true;
    }
    if (acknowledge)
        send_ack(c);
}

/* Inbound dispatch */

void handle_ip(const uint8_t *src_mac, const uint8_t *p, unsigned int len)
{
    if (len < 20 || (p[0] >> 4) != 4)
        return;
    const unsigned int ihl = (p[0] & 0x0F) * 4;
    unsigned int total = get16(p + 2);
    if (ihl < 20 || total < ihl || total > len)
        return;
    const uint8_t proto = p[9];
    const uint8_t *src = p + 12, *dst = p + 16;
    const uint8_t *body = p + ihl;
    const unsigned int blen = total - ihl;

    if (!memcmp(src, REMOTE_IP, 4)) {
        learn_remote(src_mac);
        link.addressed = true;
    }

    if (proto == PROTO_UDP && blen >= 8 && get16(body + 2) == 67) {
        handle_dhcp(body + 8, blen - 8);
    } else if (proto == PROTO_ICMP && blen >= 8 && body[0] == 8
               && !memcmp(dst, HOST_IP, 4)) {
        uint8_t reply[1500];
        memcpy(reply, body, blen);
        reply[0] = 0;             // echo reply
        put16(reply + 2, 0);
        put16(reply + 2, checksum(reply, blen));
        send_ip(PROTO_ICMP, src, src_mac, reply, blen);
    } else if (proto == PROTO_TCP && !memcmp(dst, HOST_IP, 4)
               && !memcmp(src, REMOTE_IP, 4)) {
        handle_tcp(body, blen);
    }
}

void handle_frame(uint8_t *frame, unsigned int len)
{
    if (len < 18)
        return;
    // The trailer is a CRC32 of the frame. A sender that pads short
    // transfers leaves a byte after it; accept either.
    unsigned int n = len - 4;
    uint32_t crc = frame[n] | (frame[n + 1] << 8) | (frame[n + 2] << 16)
        | ((uint32_t)frame[n + 3] << 24);
    if (crc32(frame, n) != crc && len >= 19) {
        n = len - 5;
        crc = frame[n] | (frame[n + 1] << 8) | (frame[n + 2] << 16)
            | ((uint32_t)frame[n + 3] << 24);
        if (crc32(frame, n) != crc) {
            debug("dropping a %u byte frame with a bad CRC", len);
            return;
        }
    }
    const uint16_t ethertype = get16(frame + 12);
    if (ethertype == ETH_ARP)
        handle_arp(frame + 14, n - 14);
    else if (ethertype == ETH_IP)
        handle_ip(frame + 6, frame + 14, n - 14);
}

/*
 * Read and handle one frame, waiting up to timeout_ms for it. Returns whether
 * a frame arrived.
 */
bool read_frames(unsigned int timeout_ms)
{
    if (link.gone)
        return false;
    uint8_t frame[MAX_FRAME];
    int got = 0;
    int err = libusb_bulk_transfer(link.dev, link.ep_in, frame, sizeof(frame),
                                   &got, timeout_ms ? timeout_ms : 1);
    if (err == LIBUSB_ERROR_TIMEOUT && got == 0)
        return false;
    if (err == LIBUSB_ERROR_NO_DEVICE || err == LIBUSB_ERROR_IO
        || err == LIBUSB_ERROR_PIPE) {
        debug("the remote went away: %s", libusb_error_name(err));
        link.gone = true;
        return false;
    }
    if (got > 0)
        handle_frame(frame, got);
    return got > 0;
}

/* Keep the connections moving: retransmit what has gone unacknowledged. */
void service(void)
{
    const unsigned long t = now_ms();
    for (unsigned int i = 0; i < MAX_CONNECTIONS; i++) {
        Connection &c = link.conn[i];
        if (!c.used || c.state == TCP_CLOSED)
            continue;
        if (c.state == TCP_SYN_SENT && t - c.sent_at > c.rto) {
            if (++c.retransmits > MAX_RETRANSMITS) {
                c.state = TCP_CLOSED;
                continue;
            }
            send_segment(c, c.snd_una, TCP_SYN, NULL, 0);
            c.sent_at = t;
            c.rto = c.rto * 2 < RTO_MAX_MS ? c.rto * 2 : RTO_MAX_MS;
        } else if (!c.unacked.empty() && t - c.sent_at > c.rto) {
            if (++c.retransmits > MAX_RETRANSMITS) {
                debug("no acknowledgement from port %u, giving up",
                      c.remote_port);
                c.state = TCP_CLOSED;
                continue;
            }
            c.rto = c.rto * 2 < RTO_MAX_MS ? c.rto * 2 : RTO_MAX_MS;
            transmit(c, c.snd_una);
        }
    }
}

bool pump(unsigned int timeout_ms)
{
    const bool got = read_frames(timeout_ms);
    service();
    return got;
}

bool find_interface(libusb_device *dev, int &number, uint8_t &in,
                    uint8_t &out, uint16_t &out_size)
{
    libusb_config_descriptor *config;
    if (libusb_get_active_config_descriptor(dev, &config))
        return false;
    bool found = false;
    for (int i = 0; i < config->bNumInterfaces && !found; i++) {
        const libusb_interface &intf = config->interface[i];
        for (int a = 0; a < intf.num_altsetting && !found; a++) {
            const libusb_interface_descriptor &d = intf.altsetting[a];
            if (d.bInterfaceClass != LIBUSB_CLASS_COMM
                || d.bInterfaceSubClass != 0x0A)      // MDLM
                continue;
            in = out = 0;
            for (int e = 0; e < d.bNumEndpoints; e++) {
                const libusb_endpoint_descriptor &ep = d.endpoint[e];
                if ((ep.bmAttributes & 0x03) != LIBUSB_TRANSFER_TYPE_BULK)
                    continue;
                if (ep.bEndpointAddress & LIBUSB_ENDPOINT_IN) {
                    in = ep.bEndpointAddress;
                } else {
                    out = ep.bEndpointAddress;
                    out_size = ep.wMaxPacketSize;
                }
            }
            if (in && out) {
                number = d.bInterfaceNumber;
                found = true;
            }
        }
    }
    libusb_free_config_descriptor(config);
    return found;
}

int open_device(void)
{
    libusb_device **list;
    ssize_t count = libusb_get_device_list(link.ctx, &list);
    if (count < 0)
        return LC_ERROR_OS;
    int result = LC_ERROR_CONNECT;
    for (ssize_t i = 0; i < count; i++) {
        libusb_device_descriptor desc;
        if (libusb_get_device_descriptor(list[i], &desc)
            || desc.idVendor != VENDOR_LOGITECH
            || desc.idProduct != PRODUCT_USBNET)
            continue;
        int number;
        uint8_t in, out;
        uint16_t out_size = 64;
        if (!find_interface(list[i], number, in, out, out_size)) {
            debug("usbnet remote without an MDLM interface");
            continue;
        }
        int err = libusb_open(list[i], &link.dev);
        if (err) {
            debug("cannot open the usbnet remote: %s", libusb_error_name(err));
            result = LC_ERROR_OS;
            continue;
        }
        // An OS driver may hold it (zaurus on Linux): let libusb move it
        // aside while we have it, and give it back afterwards.
        libusb_set_auto_detach_kernel_driver(link.dev, 1);
        err = libusb_claim_interface(link.dev, number);
        if (err) {
            debug("cannot claim the usbnet remote: %s", libusb_error_name(err));
            libusb_close(link.dev);
            link.dev = NULL;
            result = LC_ERROR_OS;
            continue;
        }
        link.interface = number;
        link.ep_in = in;
        link.ep_out = out;
        link.out_packet_size = out_size ? out_size : 64;
        result = 0;
        break;
    }
    libusb_free_device_list(list, 1);
    return result;
}

} // namespace

int UsbNetLink_Open(unsigned int timeout_ms)
{
    UsbNetLink_Close();
    link.gone = link.addressed = link.remote_mac_known = false;
    link.ip_id = now_ms() & 0xFFFF;
    link.next_port = 49152 + (now_ms() % 8192);

    if (libusb_init(&link.ctx))
        return LC_ERROR_OS;
    int err = open_device();
    if (err) {
        UsbNetLink_Close();
        return err;
    }
    debug("claimed the usbnet remote, waiting for it to take its address");

    // It either asks for an address (DHCP) or already has one, in which case
    // asking who has 169.254.1.2 finds it.
    const unsigned long deadline = now_ms() + timeout_ms;
    unsigned long next_probe = 0;
    while (!link.addressed && !link.gone && now_ms() < deadline) {
        if (now_ms() >= next_probe) {
            static const uint8_t zero_mac[6] = {0, 0, 0, 0, 0, 0};
            send_arp(1, zero_mac, REMOTE_IP, BROADCAST_MAC);
            next_probe = now_ms() + 500;
        }
        pump(POLL_MS);
    }
    if (!link.addressed) {
        debug("the usbnet remote did not come up");
        UsbNetLink_Close();
        return LC_ERROR_CONNECT;
    }
    // Its address, as distinct from its MAC, is all a REQUEST proves; make
    // sure we can address frames to it.
    while (!link.remote_mac_known && !link.gone && now_ms() < deadline)
        pump(POLL_MS);
    return link.remote_mac_known ? 0 : LC_ERROR_CONNECT;
}

void UsbNetLink_Close(void)
{
    if (link.dev) {
        libusb_release_interface(link.dev, link.interface);
        libusb_close(link.dev);
        link.dev = NULL;
    }
    if (link.ctx) {
        libusb_exit(link.ctx);
        link.ctx = NULL;
    }
    for (unsigned int i = 0; i < MAX_CONNECTIONS; i++) {
        link.conn[i].used = false;
        link.conn[i].state = TCP_CLOSED;
        std::vector<uint8_t>().swap(link.conn[i].unacked);
        std::vector<uint8_t>().swap(link.conn[i].received);
    }
}

int UsbNetLink_Connect(uint16_t port, unsigned int timeout_ms)
{
    if (!link.dev || link.gone)
        return -LC_ERROR_OS_NET;
    int slot = -1;
    for (unsigned int i = 0; i < MAX_CONNECTIONS && slot < 0; i++) {
        if (!link.conn[i].used)
            slot = i;
    }
    if (slot < 0)
        return -LC_ERROR;
    Connection &c = link.conn[slot];
    c.used = true;
    c.state = TCP_SYN_SENT;
    c.local_port = link.next_port++;
    if (link.next_port < 49152)
        link.next_port = 49152;
    c.remote_port = port;
    c.snd_una = c.snd_nxt = ((uint32_t)now_ms() * 2654435761u) ^ port;
    c.rcv_nxt = 0;
    c.peer_window = 0;
    c.mss = 536;
    c.unacked.clear();
    c.received.clear();
    c.rto = RTO_MIN_MS;
    c.retransmits = 0;
    send_segment(c, c.snd_una, TCP_SYN, NULL, 0);
    c.sent_at = now_ms();

    const unsigned long deadline = now_ms() + timeout_ms;
    while (c.state == TCP_SYN_SENT && !link.gone && now_ms() < deadline)
        pump(POLL_MS);
    if (c.state != TCP_OPEN) {
        debug("cannot connect to port %u", port);
        c.used = false;
        return -LC_ERROR_CONNECT;
    }
    debug("connected to port %u", port);
    return slot;
}

int UsbNetLink_Send(int conn, const uint8_t *data, unsigned int len)
{
    if (conn < 0 || conn >= (int)MAX_CONNECTIONS || !link.conn[conn].used)
        return LC_ERROR;
    Connection &c = link.conn[conn];
    if (c.state != TCP_OPEN && c.state != TCP_PEER_CLOSED)
        return LC_ERROR_OS_NET;
    const uint32_t start = c.snd_una + c.unacked.size();
    c.unacked.insert(c.unacked.end(), data, data + len);
    c.retransmits = 0;
    transmit(c, start);
    // Like a blocking send(): return once the remote has it all.
    while (!c.unacked.empty() && c.state != TCP_CLOSED && !link.gone) {
        pump(POLL_MS);
        if (!c.unacked.empty() && c.peer_window
            && seq_lt(c.snd_nxt, c.snd_una + c.unacked.size())
            && seq_lt(c.snd_nxt, c.snd_una + c.peer_window)) {
            transmit(c, c.snd_nxt);   // the window opened further
        }
    }
    return c.unacked.empty() ? 0 : LC_ERROR_OS_NET;
}

int UsbNetLink_Recv(int conn, uint8_t *data, unsigned int &len,
                    unsigned int timeout_ms)
{
    const unsigned int capacity = len;
    len = 0;
    if (conn < 0 || conn >= (int)MAX_CONNECTIONS || !link.conn[conn].used)
        return LC_ERROR;
    Connection &c = link.conn[conn];
    const unsigned long deadline = now_ms() + timeout_ms;
    while (c.received.empty() && c.state == TCP_OPEN && !link.gone
           && now_ms() < deadline) {
        pump(POLL_MS);
    }
    // Collect whatever else of this reply is already queued, stopping as soon
    // as the link goes quiet.
    while (!c.received.empty() && c.state == TCP_OPEN && pump(1)) {
    }
    if (c.received.empty()) {
        if (c.state == TCP_PEER_CLOSED)
            return 0;             // orderly end of stream
        return LC_ERROR_OS_NET;
    }
    const unsigned int was_full = c.received.size() >= RX_WINDOW;
    len = c.received.size() < capacity ? c.received.size() : capacity;
    memcpy(data, &c.received[0], len);
    c.received.erase(c.received.begin(), c.received.begin() + len);
    if (was_full)
        send_ack(c);              // tell it the window is open again
    return 0;
}

void UsbNetLink_Disconnect(int conn)
{
    if (conn < 0 || conn >= (int)MAX_CONNECTIONS || !link.conn[conn].used)
        return;
    Connection &c = link.conn[conn];
    if ((c.state == TCP_OPEN || c.state == TCP_PEER_CLOSED) && !link.gone) {
        send_segment(c, c.snd_nxt, TCP_FIN | TCP_ACK, NULL, 0);
        c.snd_nxt += 1;
        const unsigned long deadline = now_ms() + 500;
        while (now_ms() < deadline && c.state != TCP_CLOSED
               && seq_lt(c.snd_una, c.snd_nxt) && !link.gone) {
            pump(POLL_MS);
        }
    }
    c.used = false;
    c.state = TCP_CLOSED;
    c.unacked.clear();
    c.received.clear();
}
