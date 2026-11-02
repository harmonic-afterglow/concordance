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
 * (C) Copyright Phil Dibowitz 2010
 */

#include <string.h>
#ifndef _WIN32
#include <unistd.h>                 // sleep(), for the READ_REGION busy wait
#endif
#include "libconcord.h"
#include "lc_internal.h"
#include "hid.h"
#include "remote.h"
#include "usblan.h"
#include "protocol_z.h"
#include "remote_z_learn/single.h"
#include "remote_z_learn/start.h"
#include "remote_z_learn/stop.h"
#include "remote_z_learn/stream.h"
#include "remote_z_learn/data.h"

/* Have we acked the syn packet yet? */
static bool SYN_ACKED = false;
static unsigned int last_seq;
static unsigned int last_ack;
static unsigned int last_payload_bytes;

int TCP_Ack(bool increment_ack = false, bool fin = false) {
    uint8_t pkt[HID_UDP_MAX_PACKET_SIZE];

    /*
     * Note: It's the caller's responsibility to ensure we've already
     * seen the SYN packet.
     */

    uint8_t seq;
    uint8_t ack;
    uint8_t flags;

    seq = last_ack;
    ack = last_seq + last_payload_bytes;
    if (increment_ack)
        ack++;
    flags = TYPE_TCP_ACK;
    if (fin)
        flags |= TYPE_TCP_FIN;
    pkt[0] = 3;
    pkt[1] = flags;
    pkt[2] = seq;
    pkt[3] = ack;

    debug_packet("Writing packet:");
#ifdef _DEBUG
    for (int i = 0; i <= pkt[0]; i++) {
        fprintf(stderr, "%02X ", pkt[i]);
    }
    fprintf(stderr, "\n");
#endif

    return HID_WriteReport(pkt);
}


/*
 * The HID-based zwave remotes have two modes: so called "UDP" and "TCP". Do
 * not confuse these with the network protocols of similar names.
 *
 * The non-HID based zwave remotes only use "TCP".
 *
 * For more information on the various Read/Write functions here and how they
 * fit together, see the specs/protocol_z.txt file.
 */
int CRemoteZ_HID::UDP_Write(uint8_t typ, uint8_t cmd, uint32_t len,
                            uint8_t *data)
{
    if (len > 60)
        return LC_ERROR;
    uint8_t pkt[HID_UDP_MAX_PACKET_SIZE];
    pkt[0] = 3+len;
    pkt[1] = 1; // UDP
    pkt[2] = typ;
    pkt[3] = 0xFF & cmd;
    if (data && len)
        memcpy(pkt + 4, data, len);

    debug_packet("Writing packet:");
#ifdef _DEBUG
    for (int i = 0; i <= pkt[0]; i++) {
        fprintf(stderr, "%02X ", pkt[i]);
    }
    fprintf(stderr, "\n");
#endif

    return HID_WriteReport(pkt);
}

int CRemoteZ_HID::UDP_Read(uint8_t &status, uint32_t &len, uint8_t *data)
{
    uint8_t pkt[HID_UDP_MAX_PACKET_SIZE];
    int err;
    if ((err = HID_ReadReport(pkt))) {
        return LC_ERROR_READ;
    }

    debug_packet("Reading packet:");
#ifdef _DEBUG
    for (int i = 0; i <= pkt[0]; i++) {
        fprintf(stderr, "%02X ", pkt[i]);
    }
    fprintf(stderr, "\n");
#endif

    if (pkt[0] < 4) {
        return LC_ERROR;
    }
    if (pkt[0] > 4) {
        status = pkt[4];
    }
    len = pkt[0] - 4;
    /*
     * pkt[0] is the index of the last byte, which means it is equal to the
     * length of the packet minus one byte.  We want to copy everything but the
     * first byte, so we copy pkt[0] bytes.
     */
    memcpy(data, pkt + 1, pkt[0]);
    return 0;
}

int CRemoteZ_HID::TCP_Write(uint8_t typ, uint8_t cmd, uint32_t len,
                            uint8_t *data)
{
    uint8_t pkt[HID_UDP_MAX_PACKET_SIZE];

    /*
     * Note: It's the caller's responsibility to ensure we've already
     * seen the SYN packet.
     */

    uint8_t seq;
    uint8_t ack;
    uint8_t flags;

    if (!SYN_ACKED) {
        seq = 0x28;
        ack = last_seq + 1;
        flags = TYPE_TCP_ACK | TYPE_TCP_SYN;
        SYN_ACKED = true;
    } else {
        seq = last_ack;
        ack = last_seq + last_payload_bytes;
        flags = TYPE_TCP_ACK;
    }

    if (len > 60)
        return LC_ERROR;
    pkt[0] = 5+len;
    pkt[1] = flags;
    pkt[2] = seq;
    pkt[3] = ack;
    pkt[4] = typ;
    pkt[5] = cmd;
    if (data && len)
        memcpy(pkt + 6, data, len);

    debug_packet("Writing packet:");
#ifdef _DEBUG
    for (int i = 0; i <= pkt[0]; i++) {
        fprintf(stderr, "%02X ", pkt[i]);
    }
    fprintf(stderr, "\n");
#endif

    return HID_WriteReport(pkt);
}


int CRemoteZ_HID::TCP_Read(uint8_t &status, uint32_t &len, uint8_t *data)
{
    uint8_t pkt[HID_UDP_MAX_PACKET_SIZE];
    int err;
    /*
     * Many TCP operations can take a while, like computing checksums,
     * and it will be a while before we get a response. So we set the
     * timeout to 30 seconds.
     */
    if ((err = HID_ReadReport(pkt, 30000))) {
        return LC_ERROR_READ;
    }

    debug_packet("Reading packet:");
#ifdef _DEBUG
    for (int i = 0; i <= pkt[0]; i++) {
        fprintf(stderr, "%02X ", pkt[i]);
    }
    fprintf(stderr, "\n");
#endif

    if (pkt[0] < 3) {
        return LC_ERROR;
    }
    /*
     * pkt[0] is the index of the last byte, which means it is equal to the
     * length of packet minus one byte.  'len' is expected to be set to the
     * payload size.  To get the payload size we subtract both the TCP and
     * UDP headers from pkt[0] and then add one.
     */
    len = pkt[0] - HID_TCP_HDR_SIZE - HID_UDP_HDR_SIZE + 1;
    last_seq = pkt[2];
    last_ack = pkt[3];
    last_payload_bytes = len + HID_UDP_HDR_SIZE; // tcp payload size
    //if(!len) return 0;
    //memcpy(data, pkt + 6, len);
    // include headers, minus the size
    memcpy(data, pkt + 1, len + HID_TCP_HDR_SIZE + HID_UDP_HDR_SIZE - 1);
    return 0;
}

int CRemoteZ_HID::Write(uint8_t typ, uint8_t cmd, uint32_t len, uint8_t *data)
{
    return UDP_Write(typ, cmd, len, data);
}

int CRemoteZ_HID::Read(uint8_t &status, uint32_t &len, uint8_t *data)
{
    return UDP_Read(status, len, data);
}

int CRemoteZ_HID::ParseParams(uint32_t len, uint8_t *data, TParamList &pl)
{
    debug("ParseParams, %02x %02x %02x %02x %02x %02x\n", data[0], data[1],
          data[2], data[3], data[4], data[5]);
    switch (data[2]) {
        case COMMAND_GET_SYSTEM_INFO:
            pl.count = 8;
            pl.p[0] = data + 4;
            pl.p[1] = data + 6;
            pl.p[2] = data + 8;
            pl.p[3] = data + 10;
            pl.p[4] = data + 12;
            pl.p[5] = data + 14;
            pl.p[6] = data + 15;
            pl.p[7] = data + 17;
            break;
        case COMMAND_GET_CURRENT_TIME:
            pl.count = (len > 16) ? 12 : 8;
            pl.p[0] = data + 4;
            pl.p[1] = data + 6;
            pl.p[2] = data + 7;
            pl.p[3] = data + 8;
            pl.p[4] = data + 9;
            pl.p[5] = data + 10;
            pl.p[6] = data + 11;
            pl.p[7] = data + 12;
            pl.p[8] = data + 14;
            pl.p[9] = data + 16;
            pl.p[10] = data + 18;
            pl.p[11] = data + 20;
            break;
        case COMMAND_GET_GUID:
            pl.count = 1;
            pl.p[0] = data + 4;
            break;
    }
    return 0;
}


int CRemoteZ_USBNET::Write(uint8_t typ, uint8_t cmd, uint32_t len,
                           uint8_t *data)
{
    if (len > USBNET_MAX_PACKET_SIZE) {
        return LC_ERROR;
    }

    static const uint8_t service_type = SERVICE_FAMILY_CLIENT;
    const bool request = (typ == TYPE_REQUEST);
    const uint8_t status = STATUS_OK;

    uint8_t pkt[USBNET_MAX_PACKET_SIZE+3]; /* add standard 3-byte header */
    pkt[0] = (service_type << 4) | ((cmd >> 8) & 0x0F);
    pkt[1] = cmd & 0xFF;
    pkt[2] = request ? 0x80 : (status & 0x7F);

    if (len && data) {
        memcpy(pkt + 3, data, len);
        len += 3;
    } else {
        pkt[3] = 0x00;    // Param count
        len = 4;
    }

    // Every request but the ones a transfer repeats for each block, so the
    // trace shows which of them a remote did not answer.
    if (cmd != COMMAND_READ_REGION_DATA && cmd != COMMAND_WRITE_UPDATE_DATA)
        debug("request %02X, %u bytes", cmd, len);
    return UsbLan_Write(len, pkt);
}

/* What every reply buffer here holds: the largest packet and its header. */
static const uint32_t USBNET_REPLY_ROOM = USBNET_MAX_PACKET_SIZE + 3;

int CRemoteZ_USBNET::Read(uint8_t &status, uint32_t &len, uint8_t *data)
{
    uint8_t buf[1600];
    len = sizeof(buf);
    int err;
    if ((err = UsbLan_Read(len, buf))) {
        debug("no reply (error %d)", err);
        return err;
    }

    if (len >= 3 && buf[1] == COMMAND_GET_GUID) {
        // The remote's serial numbers: not for a log people post.
        debug("reply, %u bytes: %02X %02X %02X ...", len, buf[0], buf[1],
              buf[2]);
    } else if (len < 3 || buf[1] != COMMAND_READ_REGION_DATA) {
        // Its start: the command it answers, its status, its parameters.
        char hex[3 * 24 + 1] = "";
        for (unsigned int i = 0; i < len && i < 24; i++)
            snprintf(hex + 3 * i, 4, " %02X", buf[i]);
        debug("reply, %u bytes:%s%s", len, hex, len > 24 ? " ..." : "");
    }

    if (len > USBNET_REPLY_ROOM) {
        // More than any reply is: keep what fits rather than run past the
        // caller's buffer.
        debug("reply of %u bytes cut to %u", len, USBNET_REPLY_ROOM);
        len = USBNET_REPLY_ROOM;
    }
    memcpy(data, buf, len);

    return err;
}

int CRemoteZ_USBNET::ParseParams(uint32_t len, uint8_t *data, TParamList &pl)
{
    unsigned int n = 0;
    unsigned int i = 4;
    while (i < len) {
        unsigned int param_len = data[i];
        switch (param_len & 0xC0) {
            case 0x00:
            case 0x80:
                param_len &= 0x3F;
                break;
            case 0x40:
                param_len = (param_len & 0x3F) * 4;
                break;
            case 0xC0:
                param_len = (param_len & 0x3F) * 512;
                break;
        }
        ++i;
        if (n == sizeof(pl.p) / sizeof(pl.p[0])) {
            debug("more parameters than %u; the rest ignored", n);
            break;
        }
        pl.p[n++] = data+i;
#ifdef _DEBUG
        fprintf(stderr, "DEBUG (%s): %3i:", __FUNCTION__, param_len);
        for(unsigned int j = 0; j < param_len; ++j)
            fprintf(stderr, " %02X", data[i+j]);
        fprintf(stderr, "\n");
#endif
        i += param_len;
    }

    //data[3];    // Number of parameters
    pl.count = n;

    return 0;
}

int CRemoteZ_USBNET::TCPSendAndCheck(uint8_t cmd, uint32_t len, uint8_t *data)
{
    int err = 0;
    uint8_t status;
    unsigned int rlen;
    uint8_t rsp[USBNET_REPLY_ROOM];

    if ((err = Write(TYPE_REQUEST, cmd, len, data))) {
        debug("Failed to send request %02X", cmd);
        return LC_ERROR_WRITE;
    }

    if ((err = Read(status, rlen, rsp))) {
        debug("Failed to read from remote");
        return LC_ERROR_READ;
    }

    if (rsp[2] != TYPE_RESPONSE) {
        debug("Packet didn't have response bit!");
        return LC_ERROR;
    }

    if (rsp[1] != cmd) {
        debug("The cmd bit didn't match our request packet");
        return LC_ERROR;
    }

    return 0;
}

int CRemoteZ_USBNET::UpdateConfig(const uint32_t len, const uint8_t *wr,
                                  lc_callback cb, void *cb_arg,
                                  uint32_t cb_stage, uint32_t xml_size,
                                  uint8_t *xml)
{
    return WriteRegion(REGION_USER_CONFIG, len, wr, cb, cb_arg,
                       LC_CB_STAGE_WRITE_CONFIG);
}

/*
 * Write a whole region: start an update of it, send its size, its data 1024
 * bytes at a time, then ask for its checksum and finish. The user config is
 * one region, 4, on the 900, 1000 and 1100; the others are the firmware (a
 * Harmony 900's 1, 2, 12, 14, 16), which Logitech's software wrote with this
 * same sequence, each region file sent as it is in the firmware package. A
 * Harmony 1000 accepts region 4 like the others (its region manager checks
 * only that the region is valid before an update) but will not hand it back.
 *
 * Writing a region cannot be undone from here, and a bad region 1 (Safe Mode)
 * or 2 (the program) leaves a remote that will not start. The caller chooses
 * the region; nothing here writes more than the one it is given.
 */
int CRemoteZ_USBNET::WriteRegion(uint8_t region, const uint32_t len,
                                 const uint8_t *wr, lc_callback cb,
                                 void *cb_arg, uint32_t cb_stage)
{
    int err = 0;
    int cb_count = 0;

    cb(LC_CB_STAGE_INITIALIZE_UPDATE, cb_count++, 0, 2,
       LC_CB_COUNTER_TYPE_STEPS, cb_arg, NULL);

    /* ACK it with a command to start an update */
    debug("START_UPDATE");
    // 2 parameters, each 1 byte.
    // 1st parameter "flags" seems to always be 0.
    uint8_t cmd[60] = { 0x02, 0x01, 0x00, 0x01, region };
    if ((err = TCPSendAndCheck(COMMAND_START_UPDATE, 5, cmd))) {
        return err;
    }

    cb(LC_CB_STAGE_INITIALIZE_UPDATE, cb_count++, 1, 2,
        LC_CB_COUNTER_TYPE_STEPS, cb_arg, NULL);

    /* write update-header */
    debug("UPDATE_HEADER");
    cmd[0] = 0x02; // 2 parameters
    cmd[1] = 0x04; // 1st parameter 4 bytes (size)
    cmd[2] = (len & 0xFF000000) >> 24; 
    cmd[3] = (len & 0x00FF0000) >> 16;
    cmd[4] = (len & 0x0000FF00) >> 8;
    cmd[5] = (len & 0x000000FF);
    cmd[6] = 0x01; // 2nd parameter 1 byte (region id)
    cmd[7] = region;
    if ((err = TCPSendAndCheck(COMMAND_WRITE_UPDATE_HEADER, 8, cmd))) {
        return err;
    }

    cb(LC_CB_STAGE_INITIALIZE_UPDATE, cb_count++, 2, 2,
       LC_CB_COUNTER_TYPE_STEPS, cb_arg, NULL);
    cb_count = 0;

    /* write data */
    debug("UPDATE_DATA");
    uint32_t pkt_len;
    uint32_t tlen = len;
    uint8_t *wr_ptr = const_cast<uint8_t*>(wr);
    uint8_t tmp_pkt[1033];
    tmp_pkt[0] = 0x03; // 3 parameters
    tmp_pkt[1] = 0x01; // 1st parameter, 1 byte (region id)
    tmp_pkt[2] = region;
    tmp_pkt[3] = 0xC2; // 2nd parameter, 1024 bytes (data)
    tmp_pkt[1028] = 0x04; // 3rd parameter, 4 bytes (length)
    while (tlen) {
        pkt_len = 1024; // max packet length seems to be 1024
        if (tlen < pkt_len) {
            pkt_len = tlen;
        }
        tlen -= pkt_len;

        memcpy(&tmp_pkt[4], wr_ptr, pkt_len);
        tmp_pkt[1029] = (pkt_len & 0xFF000000) >> 24;
        tmp_pkt[1030] = (pkt_len & 0x00FF0000) >> 16;
        tmp_pkt[1031] = (pkt_len & 0x0000FF00) >> 8;
        tmp_pkt[1032] = (pkt_len & 0x000000FF);

        debug_packet("DATA %d, sending %d bytes, %d bytes left", cb_count,
            pkt_len, tlen);

        if ((err = TCPSendAndCheck(COMMAND_WRITE_UPDATE_DATA, 1033, tmp_pkt))) {
            return err;
        }
        wr_ptr += pkt_len;

        if (cb) {
            cb(cb_stage, cb_count++, (int)(wr_ptr - wr), len,
               LC_CB_COUNTER_TYPE_BYTES, cb_arg, NULL);
        }
    }

    /* write update-done */
    cb_count = 0;
    cb(LC_CB_STAGE_FINALIZE_UPDATE, cb_count++, 0, 3, LC_CB_COUNTER_TYPE_STEPS,
       cb_arg, NULL);

    debug("UPDATE_DATA_DONE");
    cmd[0] = 0x01; // 1 parameter
    cmd[1] = 0x01; // 1st parameter 1 byte (region id)
    cmd[2] = region;
    if ((err = TCPSendAndCheck(COMMAND_WRITE_UPDATE_DATA_DONE, 3, cmd))) {
        return err;
    }

    cb(LC_CB_STAGE_FINALIZE_UPDATE, cb_count++, 1, 3, LC_CB_COUNTER_TYPE_STEPS,
       cb_arg, NULL);

    /* send get-cheksum */
    debug("GET_CHECKSUM");
    cmd[0] = 0x02; // 2 parameters
    cmd[1] = 0x02; // 1st parameter 2 bytes (seed)
    cmd[2] = 0xFF; // seed seems to always be FF
    cmd[3] = 0xFF; // seed seems to always be FF
    cmd[4] = 0x01; // 2nd parameter 1 byte (region id)
    cmd[5] = region;
    if ((err = TCPSendAndCheck(COMMAND_GET_UPDATE_CHECKSUM, 6, cmd))) {
        return err;
    }

    cb(LC_CB_STAGE_FINALIZE_UPDATE, cb_count++, 2, 3, LC_CB_COUNTER_TYPE_STEPS,
       cb_arg, NULL);

    /* send finish-update */
    debug("FINISH_UPDATE");
    cmd[0] = 0x02; // 2 parameters
    cmd[1] = 0x01; // 1st parameter 1 byte (validate)
    cmd[2] = 0x01; // validate?
    cmd[3] = 0x01; // 2nd parameter 1 byte (region id)
    cmd[4] = region;
    if ((err = TCPSendAndCheck(COMMAND_FINISH_UPDATE, 5, cmd))) {
        return err;
    }

    cb(LC_CB_STAGE_FINALIZE_UPDATE, cb_count++, 3, 3, LC_CB_COUNTER_TYPE_STEPS,
       cb_arg, NULL);

    return 0;
}

int CRemoteZ_USBNET::GetTime(const TRemoteInfo &ri, THarmonyTime &ht)
{
    int err = 0;
    if ((err = Write(TYPE_REQUEST, COMMAND_GET_CURRENT_TIME))) {
        debug("Failed to write to remote");
        return LC_ERROR_WRITE;
    }
    uint8_t time[USBNET_REPLY_ROOM];
    unsigned int len;
    uint8_t status;
    if ((err = Read(status, len, time))) {
        debug("Failed to read to remote");
        return LC_ERROR_READ;
    }

    if (time[2] != TYPE_RESPONSE || time[1] != COMMAND_GET_CURRENT_TIME) {
        debug("Incorrect response type from Get Time");
        return LC_ERROR_INVALID_DATA_FROM_REMOTE;
    }

    CRemoteZ_Base::TParamList pl;
    ParseParams(len, time, pl);

    ht.year = GetWord(pl.p[0]);
    ht.month = *pl.p[1];
    ht.day = *pl.p[2];
    ht.hour = *pl.p[3];
    ht.minute = *pl.p[4];
    ht.second = *pl.p[5];
    ht.dow = *pl.p[6]&7;
    ht.utc_offset = static_cast<int16_t>(GetWord(pl.p[7]));
    if (pl.count > 11) {
        ht.timezone = reinterpret_cast<char*>(pl.p[11]);
        ht.timezone[3] = '\0';
    } else {
        ht.timezone = "";
    }

    return 0;
}

int CRemoteZ_USBNET::SetTime(const TRemoteInfo &ri, const THarmonyTime &ht,
                             lc_callback cb, void *cb_arg, uint32_t cb_stage)
{
    debug("SetTime");
    int err = 0;

    uint8_t tsv[32] = {
        0x0C, // 12 parameters
        0x02, static_cast<uint8_t>(ht.year >> 8),
        static_cast<uint8_t>(ht.year), // 2 bytes
        0x01, static_cast<uint8_t>(ht.month),
        0x01, static_cast<uint8_t>(ht.day),
        0x01, static_cast<uint8_t>(ht.hour),
        0x01, static_cast<uint8_t>(ht.minute),
        0x01, static_cast<uint8_t>(ht.second),
        0x01, static_cast<uint8_t>(ht.dow),
        // utcOffset
        0x02, 0, 0, // 2 bytes - 900 doesn't seem to accept this
        // 0s
        0x02, 0, 0, // 2 bytes
        0x02, 0, 0, // 2 bytes
        0x02, 0, 0, // 2 bytes
        0x83, 0, 0, 0 // 900 doesn't seem to accept this, don't bother
        };

    if ((err = TCPSendAndCheck(COMMAND_UPDATE_TIME, 32, tsv))) {
        debug("Failed to write to remote");
        return err;
    }

    return 0;
}


int CRemoteZ_USBNET::SetIrMode(int mode, uint32_t stream_timeout_ms)
{
  if (mode == LC_LEARN_SINGLE || mode == LC_LEARN_STREAM) {
    ir_learn_mode = mode;
  } else {
    return -1;
  }
  ir_stream_timeout_ms = stream_timeout_ms;
  return 0;
}

int CRemoteZ_USBNET::LearnIR(uint32_t *freq, uint32_t **ir_signal,
                             uint32_t *ir_signal_length, lc_callback cb,
                             void *cb_arg, uint32_t cb_stage)
{
    int err = 0;

    *freq = 0;
    *ir_signal_length = 0;
    *ir_signal = nullptr;

    if ((err = SendLearnStart())) {
        debug("Failed starting learn mode");
        return err;
    }

    if (ir_learn_mode == LC_LEARN_STREAM) {
      err = ReadIrStream(freq, ir_signal, ir_signal_length, cb, cb_arg,
          cb_stage);
    } else {
      err = ReadIrData(freq, ir_signal, ir_signal_length, cb, cb_arg,
          cb_stage);
    }
    if (err) {
        SendLearnStop();  //always close!
        debug("Failed starting learn mode");
        return err;
    }

    if ((err = SendLearnStop())) {
        debug("Failed stopping learn mode");
        return err;
    }

    return 0;
}

int CRemoteZ_USBNET::SendLearnStart()
{
    remote_z::Start start;
    uint8_t rsp[USBNET_MAX_PACKET_SIZE + 3]; /* add standard 3-byte header */

    debug("START_IR_LEARN");

    int err = 0;
    auto req = start.get();
    if ((err = Write(
             TYPE_REQUEST, COMMAND_LEARNIR_START, req.size(), req.data()))) {
        debug("Failed to write to remote");
        return LC_ERROR_WRITE;
    }
    unsigned int len;
    uint8_t status;
    if ((err = Read(status, len, rsp))) {
        debug("Failed to read to remote");
        return LC_ERROR_READ;
    }

    auto ret = start.check(std::vector<uint8_t>(rsp, rsp + len));
    if (ret != remote_z::Start::Status::OK) {
        debug("Incorrect response type from remote");
        return LC_ERROR_INVALID_DATA_FROM_REMOTE;
    }
    return 0;
}

int CRemoteZ_USBNET::SendLearnStop()
{
    remote_z::Stop stop;
    uint8_t rsp[USBNET_MAX_PACKET_SIZE + 3]; /* add standard 3-byte header */

    debug("STOP_IR_LEARN");

    int err = 0;
    auto req = stop.get();
    if ((err = Write(
             TYPE_REQUEST, COMMAND_LEARNIR_DONE, req.size(), req.data()))) {
        debug("Failed to write to remote");
        return LC_ERROR_WRITE;
    }
    unsigned int len;
    uint8_t status;
    if ((err = Read(status, len, rsp))) {
        debug("Failed to read to remote");
        return LC_ERROR_READ;
    }

    auto ret = stop.check(std::vector<uint8_t>(rsp, rsp + len));
    if (ret != remote_z::Stop::Status::OK) {
        debug("Incorrect response type from remote");
        return LC_ERROR_INVALID_DATA_FROM_REMOTE;
    }
    return 0;
}

int CRemoteZ_USBNET::ReadIrData(uint32_t *freq, uint32_t **ir_signal,
                             uint32_t *ir_signal_length, lc_callback cb,
                             void *cb_arg, uint32_t cb_stage)
{
    remote_z::Single single;
    uint8_t rsp[USBNET_MAX_PACKET_SIZE + 3]; /* add standard 3-byte header */
    int err = 0;
    int cb_count = 0;
    bool firstChunk = true;

    debug("READING_IR_DATA");

    /*
     * Caller is responsible for deallocation of *ir_signal after use.
     *
     * Loop while we haven not:
     * - any error
     * - Timeout. Timeout is set by the remote itself answering "timeout", you can't change it.
     * - EoF
     */
    while (err == 0) {
        auto req = single.get();
        if ((err = Write(TYPE_REQUEST,
                         COMMAND_LEARNIR_SINGLE,
                         req.size(),
                         req.data()))) {
            debug("Failed to write to remote");
            err = LC_ERROR_WRITE;
            break;
        }
        unsigned int len;
        uint8_t status;
        if ((err = Read(status, len, rsp))) {
            debug("Failed to read to remote");
            err = LC_ERROR_READ;
            break;
        }

        debug_packet("DATA %d, read %d bytes", cb_count, len);

        auto ret = single.addChunk(std::vector<uint8_t>(rsp, rsp + len),
                                   firstChunk);
        if (ret == remote_z::Single::Status::DONE) break;
        switch (ret) {
            case remote_z::Single::Status::OK:
                break;
            case remote_z::Single::Status::ERR_TIMEOUT:
                err = LC_ERROR_IR_TIMEOUT;
                break;
            default:
                debug("Incorrect response type from remote (%d)", (int)ret);
                err = LC_ERROR_INVALID_DATA_FROM_REMOTE;
                break;
        }

        firstChunk = false;

        if (cb) {
            cb(cb_stage,
               cb_count++,
               single.getPayload().size(),
               0,
               LC_CB_COUNTER_TYPE_STEPS,
               cb_arg,
               NULL);
        }
    }

    if (err != 0) return err;

    debug("DECODING_IR_DATA");

    //standardise
    auto payload = single.getPayload();
    if (payload.empty())
      return 0;
    auto timingStream = remote_z::TimingStream::fromMarkSegment(payload);

    //convert to libconcord format
    const auto &t = timingStream.convertMarkPause();
    *freq = single.getClock();
    *ir_signal_length = t.size();
    *ir_signal = new uint32_t[t.size()];
    for (uint32_t i = 0; i < t.size(); i++) {
      (*ir_signal)[i] = t[i];
    }

    debug("READ_IR_DONE");

    return 0;
}

int CRemoteZ_USBNET::ReadIrStream(uint32_t *freq, uint32_t **ir_signal,
                             uint32_t *ir_signal_length, lc_callback cb,
                             void *cb_arg, uint32_t cb_stage)
{
    remote_z::Stream stream;
    uint8_t rsp[USBNET_MAX_PACKET_SIZE + 3]; /* add standard 3-byte header */
    int err = 0;
    int cb_count = 0;
    bool firstChunk = true;
    chrono::milliseconds timeout(ir_stream_timeout_ms);

    debug("READING_IR_STREAM");

    auto t_start = chrono::steady_clock::now();

    /*
     * Caller is responsible for deallocation of *ir_signal after use.
     *
     * Loop while we haven not:
     * - any error
     * - timeout (not an error, we record for this amount of time)
     *   be aware that timeout is a minimum value. the remote will
     *   always fill a data frame before returning.
     */
    while (err == 0) {
        auto req = stream.get();
        if ((err = Write(TYPE_REQUEST,
                         COMMAND_LEARNIR_STREAM,
                         req.size(),
                         req.data()))) {
            debug("Failed to write to remote");
            err = LC_ERROR_WRITE;
            break;
        }
        unsigned int len;
        uint8_t status;
        if ((err = Read(status, len, rsp))) {
            debug("Failed to read to remote");
            err = LC_ERROR_READ;
            break;
        }

        debug_packet("DATA %d, read %d bytes", cb_count, len);

        auto ret = stream.addChunk(std::vector<uint8_t>(rsp, rsp + len),
                                   firstChunk);
        if (ret == remote_z::Single::Status::DONE) break;
        switch (ret) {
            case remote_z::Single::Status::OK:
                break;
            case remote_z::Single::Status::ERR_TIMEOUT:
                err = LC_ERROR_IR_TIMEOUT;
                break;
            default:
                debug("Incorrect response type from remote (%d)", (int)ret);
                err = LC_ERROR_INVALID_DATA_FROM_REMOTE;
                break;
        }

        firstChunk = false;

        if (cb) {
            cb(cb_stage,
               cb_count++,
               stream.getPayload().size(),
               0,
               LC_CB_COUNTER_TYPE_STEPS,
               cb_arg,
               NULL);
        }

        auto t_now = chrono::steady_clock::now();
        if ((t_now - t_start) > timeout) {
          break;
        }
    }

    if (err != 0) return err;

    debug("DECODING_IR_DATA");

    //standardise
    auto payload = stream.getPayload();
    if (payload.empty())
      return 0;
    auto timingStream = remote_z::TimingStream::fromMarkSegment(payload);

    //convert to libconcord format
    const auto &t = timingStream.convertMarkPause();
    *freq = stream.getClock();
    *ir_signal_length = t.size();
    *ir_signal = new uint32_t[t.size()];
    for (uint32_t i = 0; i < t.size(); i++) {
      (*ir_signal)[i] = t[i];
    }

    debug("READ_IR_DONE");

    return 0;
}

int CRemoteZ_USBNET::ReadRegion(uint8_t region, uint32_t &rgn_len, uint8_t *rd,
                                lc_callback cb, void *cb_arg, uint32_t cb_stage)
{
    // With a buffer, rgn_len comes in as its size.
    const uint32_t capacity = rgn_len;
    int err = 0;
    int cb_count = 0;
    uint8_t rsp[USBNET_REPLY_ROOM];
    unsigned int rlen;
    uint8_t status;
    CRemoteZ_Base::TParamList pl;

    debug("READ_REGION");
    // 1 parameters, 1 byte, region to read.
    uint8_t cmd[60] = { 0x01, 0x01, region };
    // A remote still finishing something - a region it was asked for and
    // refused - answers BUSY; it is asked again, for up to a minute.
    for (int busy = 0; ; busy++) {
        if ((err = Write(TYPE_REQUEST, COMMAND_READ_REGION, 3, cmd))) {
            debug("Failed to write to remote");
            return LC_ERROR_WRITE;
        }
        if ((err = Read(status, rlen, rsp))) {
            debug("Failed to read to remote");
            return LC_ERROR_READ;
        }
        if (!(rlen >= 3 && rsp[1] == COMMAND_READ_REGION &&
              rsp[2] == STATUS_BUSY) || busy == 20)
            break;
        debug("the remote is busy; asking for region %d again", region);
#ifdef _WIN32
        Sleep(3000);
#else
        sleep(3);
#endif
    }
    // A READ_REGION success carries rsp[2] == TYPE_RESPONSE, which is the same
    // value as STATUS_OK (1); any other status is the remote answering "no".
    if (rlen >= 3 && rsp[1] == COMMAND_READ_REGION && rsp[2] != STATUS_OK) {
        // An answer, and a no: the remote is still in step, and says why. A
        // Harmony 1000 answers BAD_REGION (0x0B) at once for every region but its
        // Z-Wave ones (7 and 10): its region manager reads no others, region 4
        // (the config) included.
        debug("region %d refused, status %02X", region, rsp[2]);
        return LC_ERROR_UNSUPP;
    }
    if (rsp[2] != TYPE_RESPONSE || rsp[1] != COMMAND_READ_REGION || rlen != 9 ||
        rsp[4] != 0x04) {
        debug("Incorrect response type from remote");
        return LC_ERROR_INVALID_DATA_FROM_REMOTE;
    }
    ParseParams(rlen, rsp, pl);
    rgn_len = GetWord32(pl.p[0]);
    if (rd && rgn_len > capacity) {
        // It grew since it was measured (the remote rewrites its state files
        // as it runs). Reading it would overrun rd.
        debug("region %d is %u bytes, the buffer %u", region, rgn_len,
              capacity);
        // End the read the remote has started, so it can be asked again.
        TCPSendAndCheck(COMMAND_READ_REGION_DONE, 3, cmd);
        return LC_ERROR_READ;
    }

    debug("READ_REGION_DATA");
    uint32_t pkt_len;
    unsigned int data_to_read = rgn_len;
    uint8_t *rd_ptr = rd;
    uint8_t tmp_pkt[USBNET_MAX_PACKET_SIZE+3]; /* add standard 3-byte header */
    cmd[0] = 0x01; // 1 parameter
    cmd[1] = 0x01; // 1st parameter, 1 byte (region id)
    cmd[2] = region;

    while (data_to_read) {
        if ((err = Write(TYPE_REQUEST, COMMAND_READ_REGION_DATA, 3, cmd))) {
            debug("Failed to write to remote");
            return LC_ERROR_WRITE;
        }
        if ((err = Read(status, rlen, tmp_pkt))) {
            debug("Failed to read to remote");
            return LC_ERROR_READ;
        }
        if (tmp_pkt[2] != TYPE_RESPONSE ||
            tmp_pkt[1] != COMMAND_READ_REGION_DATA) {
            debug("Incorrect response type from remote");
            return LC_ERROR_INVALID_DATA_FROM_REMOTE;
        }
        ParseParams(rlen, tmp_pkt, pl);
        if (pl.count < 3) {
            debug("Incomplete response from remote");
            return LC_ERROR_INVALID_DATA_FROM_REMOTE;
        }
        pkt_len = GetWord32(pl.p[2]);
        if (pkt_len > data_to_read) {
            debug("Remote sent %u bytes with %u left", pkt_len, data_to_read);
            return LC_ERROR_INVALID_DATA_FROM_REMOTE;
        }
        data_to_read -= pkt_len;

        if (rd) {
            memcpy(rd_ptr, pl.p[1], pkt_len);
            rd_ptr += pkt_len;
        }

        debug_packet("DATA %d, read %d bytes, %d bytes left", cb_count, pkt_len,
              data_to_read);

        if (cb) {
            cb(cb_stage, cb_count++, rgn_len - data_to_read, rgn_len,
               LC_CB_COUNTER_TYPE_BYTES, cb_arg, NULL);
        }
    }

    debug("READ_REGION_DONE");
    // 1 parameter, 1 byte, region to read.
    cmd[0] = 0x01;
    cmd[1] = 0x01;
    cmd[2] = region;
    if ((err = TCPSendAndCheck(COMMAND_READ_REGION_DONE, 3, cmd))) {
        return err;
    }

    return 0;
}

int CRemoteZ_Base::Reset(uint8_t kind)
{
    int err = 0;
    /*
     * TODO: I don't believe the zwaves have a "kind" of reset
     * ... is this needed here?
     */
    if (kind != 2) {
        return LC_ERROR;
    }

    if ((err = Write(TYPE_REQUEST, COMMAND_Z_RESET))) {
        debug("Failed to write to remote");
        return LC_ERROR_WRITE;
    }
    uint8_t rsp[USBNET_REPLY_ROOM];
    unsigned int len;
    uint8_t status;
    if ((err = Read(status, len, rsp))) {
        debug("Failed to read to remote");
        return LC_ERROR_READ;
    }

    /*
     * TODO: Either the remote is gone at this point, and reading
     * will fail, or we need a "finalize action" command afterwards,
     * in which case we should check the actual return status from
     * the remote.
     */
    /*
    if (time[1] != TYPE_RESPONSE || time[2] != COMMAND_Z_RESET) {
        return LC_ERROR_INVALID_DATA_FROM_REMOTE;
    }
    */

    return 0;
}

int CRemoteZ_Base::GetIdentity(TRemoteInfo &ri, THIDINFO &hid, lc_callback cb,
                               void *cb_arg, uint32_t cb_stage)
{
    int err = 0;
    if ((err = Write(TYPE_REQUEST, COMMAND_GET_SYSTEM_INFO))) {
        debug("Failed to write to remote");
        return LC_ERROR_WRITE;
    }
    uint8_t rsp[USBNET_REPLY_ROOM];
    unsigned int len;
    uint8_t status;
    if ((err = Read(status, len, rsp))) {
        debug("Failed to read from remote");
        return LC_ERROR_READ;
    }

    if (cb) {
        cb(cb_stage, 0, 1, 2, LC_CB_COUNTER_TYPE_STEPS, cb_arg, NULL);
    }

    CRemoteZ_Base::TParamList pl;
    ParseParams(len, rsp, pl);
    if (pl.count < 8) {
        debug("system info with %u parameters, not 8", pl.count);
        return LC_ERROR_INVALID_DATA_FROM_REMOTE;
    }

    ri.flash_mfg = 0x01;
    ri.flash_id = 0x49;
    ri.architecture = GetWord(pl.p[2]);
    ri.fw_ver_major = GetWord(pl.p[3]);
    ri.fw_ver_minor = GetWord(pl.p[4]);
    ri.fw_type = *pl.p[5];
    ri.skin = GetWord(pl.p[6]);
    const unsigned int hw = GetWord(pl.p[7]);
    ri.hw_ver_major = hw >> 8;        // ???
    ri.hw_ver_minor = (hw >> 4) & 0x0F;    // ???
    ri.hw_ver_micro = hw & 0x0F;        // 900 has this and is non-zero
    //ri.hw_ver_major = hw >> 4;
    //ri.hw_ver_minor = hw & 0x0F;
    ri.protocol = GetWord(pl.p[2]); // Seems to be the same as arch?

    setup_ri_pointers(ri);

    if (IsUSBNet()) {
        hid.vid = GetWord(pl.p[0]);
        hid.pid = GetWord(pl.p[1]);
        hid.ver = 0;
        hid.irl = 0;
        hid.orl = 0;
        hid.frl = 0;
        hid.mfg = ri.model->mfg;
        hid.prod = ri.model->model;
    }

    if ((err = Write(TYPE_REQUEST, COMMAND_GET_GUID))) {
        debug("Failed to write to remote");
        return LC_ERROR_WRITE;
    }
    if ((err = Read(status, len, rsp))) {
        debug("Failed to read from remote");
        return LC_ERROR_READ;
    }

    if (cb) {
        cb(LC_CB_STAGE_GET_IDENTITY, 1, 2, 2, LC_CB_COUNTER_TYPE_STEPS, cb_arg,
           NULL);
    }

    ParseParams(len, rsp, pl);
    if (pl.count < 1) {
        debug("no serial number in the reply");
        return LC_ERROR_INVALID_DATA_FROM_REMOTE;
    }

    make_serial(pl.p[0], ri);

    ri.max_config_size = 1;
    ri.valid_config = 1;
    if (!IsUSBNet()) {
        ri.config_bytes_used = 0;
        return 0;
    }

    // Get the User Config Region to find the config bytes used.
    if ((err = ReadRegion(REGION_USER_CONFIG, ri.config_bytes_used, NULL,
                          NULL, NULL, 0))) {
        if (err != LC_ERROR_UNSUPP)
            return err;
        // Refused, not lost: the remote answered, so it is still in step and
        // can be identified. Reading its config will fail the same way, and
        // say so then.
        debug("identifying without the size of region %d", REGION_USER_CONFIG);
        ri.config_bytes_used = 0;
    }

    // Everything below only goes into the post to Logitech's website (web.cpp),
    // which nothing needs any more. It was worked out on the 900 and 1100; a
    // remote that answers one of these requests with something else - the
    // Harmony 1000's firmware is older than either - is identified without it.
    // One that does not answer at all is another matter: its reply may still
    // arrive, as the answer to whatever is asked next, so that stays an error.
    ri.num_regions = 0;
    ri.region_ids = NULL;
    ri.region_versions = NULL;
    ri.home_id = 0;
    ri.node_id = 0;
    ri.tid = new char[1];
    ri.tid[0] = '\0';

    // 0 with the reply's parameters in out; -1 when the remote answered, but
    // not with what was asked for; an LC_ERROR when it did not answer.
    auto ask = [&](uint8_t cmd, uint32_t plen, uint8_t *params,
                   uint8_t *reply, uint32_t want, TParamList &out) -> int {
        if (Write(TYPE_REQUEST, cmd, plen, params)) {
            debug("cannot send request %02X", cmd);
            return LC_ERROR_WRITE;
        }
        if (Read(status, len, reply)) {
            debug("no reply to request %02X", cmd);
            return LC_ERROR_READ;
        }
        if (len < 4 || reply[1] != cmd || reply[2] != STATUS_OK) {
            debug("request %02X answered with status %02X; left out", cmd,
                  len >= 3 ? reply[2] : 0);
            return -1;
        }
        ParseParams(len, reply, out);
        if (out.count < want) {
            debug("request %02X answered with %u parameters, not %u; left out",
                  cmd, out.count, want);
            return -1;
        }
        return 0;
    };

    // Get region info
    uint8_t rr[] = { 1, 1, 1 }; // AddByteParam(1);
    uint8_t rgn[USBNET_REPLY_ROOM];
    if ((err = ask(COMMAND_GET_REGION_IDS, 3, rr, rgn, 1, pl)) > 0)
        return err;
    if (err == 0 && pl.count == 1) {
        const unsigned int rc = *(pl.p[0]-1) & 0x3F;
        ri.num_regions = rc + 1;
        ri.region_ids = new uint8_t[ri.num_regions];
        ri.region_versions = new char*[ri.num_regions];

        // There seems to be an implied Region 0 that the Windows
        // software requests but it is not listed in the Region IDs.
        // Region 0 goes first, then the ones the remote listed.
        for (unsigned int r = 0; r <= rc; ++r) {
            const uint8_t rn = r ? *(pl.p[0]+r-1) : 0;
            debug("Region %i", rn);
            uint8_t rv[] = { 1, 1, rn }; // AddByteParam(rn);
            uint8_t rgv[USBNET_REPLY_ROOM];
            CRemoteZ_Base::TParamList rp;
            ri.region_ids[r] = rn;
            ri.region_versions[r] = new char[8];
            ri.region_versions[r][0] = '\0';
            if ((err = ask(COMMAND_GET_REGION_VERSION, 3, rv, rgv, 1, rp)) > 0)
                return err;
            if (err == 0)
                snprintf(ri.region_versions[r], 8, "%d.%d", *(rp.p[0]+1),
                         *rp.p[0]);
        }
    }

    // Get HOMEID, NODEID
    if ((err = ask(COMMAND_GET_HOME_ID, 0, NULL, rsp, 1, pl)) > 0)
        return err;
    if (err == 0)
        ri.home_id = (*pl.p[0] << 24) + (*(pl.p[0]+1) << 16) +
                (*(pl.p[0]+2) << 8) + *(pl.p[0]+3);
    if ((err = ask(COMMAND_GET_NODE_ID, 0, NULL, rsp, 1, pl)) > 0)
        return err;
    if (err == 0)
        ri.node_id = *pl.p[0];
    // Not asked for: the "TID" in the INTERFACE_LIST and the XMLUserRFSetting
    // from the remote's web server. Only the post to Logitech's website used
    // them. A Harmony 1000 (skin 53, firmware 5.0) answers every request before
    // INTERFACE_LIST and never that one, which cost libconcord's whole 30-second
    // wait and then the identify; a remote in Safe Mode runs no web server.
    // web.cpp gets them empty.
    ri.xml_user_rf_setting = new char[1];
    ri.xml_user_rf_setting[0] = '\0';

    return 0;
}

int CRemoteZ_Base::ReadFlash(uint32_t addr, const uint32_t len, uint8_t *rd,
                             unsigned int protocol, bool verify, lc_callback cb,
                             void *cb_arg, uint32_t cb_stage)
{
    // ReadRegion is told how much rd holds; the region may have grown since
    // its size was measured, and must not be written past the buffer.
    uint32_t tmp = len;
    return ReadRegion(addr, tmp, rd, cb, cb_arg, cb_stage);
}

/*
 * When reading a config from the remote, we need to look for a sequence of
 * four bytes to determine when to stop reading the config.  The tricky part is
 * that the sequence could be split across two packets.  Thus, we need to
 * search the last three bytes of the previous packet plus the current packet.
 * This function searches for the "end of file" sequence in a set of two
 * packets.  If the sequence is found, returns the number of bytes in the
 * second packet up to and including the sequence.  Returns 0 if the sequence
 * is not found.  Parameters point to the data section of the packets.  Note for
 * the first packet, only the last 3 bytes are expected to be passed in.
 */
int FindEndSeq(uint8_t *pkt_1, uint8_t *pkt_2)
{
    uint8_t end_seq[4] = { 0x44, 0x4B, 0x44, 0x4B }; // end of file sequence
    uint8_t tmp[57]; // 3 bytes from the 1st packet, 54 bytes from the 2nd
    memcpy(&tmp, pkt_1, 3);
    memcpy(&tmp[3], pkt_2, 54);
    for (int i=0; i<54; i++) {
        if (memcmp(&end_seq, &tmp[i], 4) == 0) {
            return i + 1;
        } 
    }
    return 0;
}

int CRemoteZ_HID::ReadRegion(uint8_t region, uint32_t &rgn_len, uint8_t *rd,
                             lc_callback cb, void *cb_arg, uint32_t cb_stage)
{
    // With a buffer, rgn_len comes in as its size.
    const uint32_t capacity = rgn_len;
    int err = 0;
    int cb_count = 0;
    uint8_t rsp[USBNET_REPLY_ROOM];
    unsigned int rlen;
    uint8_t status;

    /* Start a TCP transfer */
    if ((err = Write(TYPE_REQUEST, COMMAND_INITIATE_UPDATE_TCP_CHANNEL))) {
        debug("Failed to write to remote");
        return LC_ERROR_WRITE;
    }

    /* Make sure the remote is ready to start the TCP transfer */
    if ((err = Read(status, rlen, rsp))) {
        debug("Failed to read from remote");
        return LC_ERROR_READ;
    }

    if (rsp[1] != TYPE_RESPONSE || rsp[2] !=
        COMMAND_INITIATE_UPDATE_TCP_CHANNEL) {
        return LC_ERROR;
    }

    /* Look for a SYN packet */
    debug("Looking for syn");
    if ((err = TCP_Read(status, rlen, rsp))) {
        debug("Failed to read syn from remote");
        return LC_ERROR_READ;
    }

    if (rsp[0] != TYPE_TCP_SYN) {
        debug("Not a SYN packet!");
        return LC_ERROR;
    }

    /* ACK it with a command to read a region */
    debug("READ_REGION");
    // 1 parameters, 1 byte, region to read.
    uint8_t cmd[60] = { region };
    if ((err = TCP_Write(TYPE_REQUEST, COMMAND_READ_REGION, 1, cmd))) {
        debug("Failed to write to remote");
        return LC_ERROR_WRITE;
    }
    if ((err = TCP_Read(status, rlen, rsp))) {
        debug("Failed to read to remote");
        return LC_ERROR_READ;
    }
    if (rsp[0] != TYPE_TCP_ACK || rsp[3] != TYPE_RESPONSE ||
        rsp[4] != COMMAND_READ_REGION) {
         debug("Incorrect response type from remote");
        return LC_ERROR_INVALID_DATA_FROM_REMOTE;
    }

    rgn_len = 0;

    debug("READ_REGION_DATA");
    int data_read = 0;
    uint8_t *rd_ptr = rd;
    cmd[0] = region;
    int eof_found = 0;
    uint8_t prev_pkt_tail[3] = { 0x00, 0x00, 0x00 };

    while (1) {
        if ((err = TCP_Write(TYPE_REQUEST, COMMAND_READ_REGION_DATA, 1, cmd))) {
            debug("Failed to write to remote");
            return LC_ERROR_WRITE;
        }
        if ((err = TCP_Read(status, rlen, rsp))) {
            debug("Failed to read to remote");
            return LC_ERROR_READ;
        }
        if (rsp[0] != TYPE_TCP_ACK || rsp[3] != TYPE_RESPONSE ||
            ((rsp[4] != COMMAND_READ_REGION_DATA) &&
            (rsp[4] != COMMAND_READ_REGION_DONE))) {
             debug("Incorrect response type from remote");
            return LC_ERROR_INVALID_DATA_FROM_REMOTE;
        }
        if (rsp[4] == COMMAND_READ_REGION_DONE) {
            break;
        }
        data_read += rlen;

        if (!eof_found) {
            eof_found = FindEndSeq(prev_pkt_tail, &rsp[5]);
            if (eof_found) {
                rlen = eof_found;
            }
            rgn_len += rlen;
            memcpy(&prev_pkt_tail, &rsp[56], 3);

            if (rd) {
                if (rgn_len > capacity) {
                    debug("region %d is over %u bytes, the buffer %u", region,
                          rgn_len, capacity);
                    return LC_ERROR_READ;
                }
                memcpy(rd_ptr, &rsp[5], rlen);
                rd_ptr += rlen;
            }
        }

        debug_packet("DATA %d, read %d bytes, %d bytes total", cb_count, rlen,
              data_read);

        if (cb) {
            cb(cb_stage, cb_count++, data_read, data_read+1,
               LC_CB_COUNTER_TYPE_BYTES, cb_arg, NULL);
        }
    }

    debug("FIN-ACK");
    if ((err = TCP_Ack(false, true))) {
        debug("Failed to send fin-ack");
        return LC_ERROR_WRITE;
    }

    if ((err = TCP_Read(status, rlen, rsp))) {
        debug("Failed to read from remote");
        return LC_ERROR_READ;
    }

    /* Make sure we got an ack */
    if (rsp[0] != (TYPE_TCP_ACK | TYPE_TCP_FIN)) {
        debug("Failed to read finish-update ack");
        return LC_ERROR;
    }

    if ((err = TCP_Ack(true, false))) {
        debug("Failed to ack the ack of our fin-ack");
        return LC_ERROR_WRITE;
    }

    /* Return TCP state to initial conditions */
    SYN_ACKED = false;

    if (cb) {
        cb(cb_stage, cb_count++, data_read, data_read, LC_CB_COUNTER_TYPE_BYTES,
           cb_arg, NULL);
    }

    return 0;
}

int CRemoteZ_Base::InvalidateFlash(lc_callback cb, void *cb_arg,
                                   uint32_t cb_stage)
{
    return 0;
}

int CRemoteZ_Base::EraseFlash(uint32_t addr, uint32_t len,
                              const TRemoteInfo &ri, lc_callback cb,
                              void *cb_arg, uint32_t cb_stage)
{
    return 0;
}

int CRemoteZ_Base::WriteFlash(uint32_t addr, const uint32_t len,
                              const uint8_t *wr, unsigned int protocol,
                              lc_callback cb, void *arg, uint32_t cb_stage)
{
    return 0;
}

int CRemoteZ_Base::WriteRam(uint32_t addr, const uint32_t len, uint8_t *wr)
{
    return 0;
}

int CRemoteZ_Base::ReadRam(uint32_t addr, const uint32_t len, uint8_t *rd)
{
    return 0;
}

int CRemoteZ_Base::PrepFirmware(const TRemoteInfo &ri, lc_callback cb,
                                void *cb_arg, uint32_t cb_stage)
{
    return 0;
}

int CRemoteZ_Base::FinishFirmware(const TRemoteInfo &ri, lc_callback cb,
                                  void *cb_arg, uint32_t cb_stage)
{
    return 0;
}

int CRemoteZ_Base::PrepConfig(const TRemoteInfo &ri, lc_callback cb,
                              void *cb_arg, uint32_t cb_stage)
{
    return 0;
}

int CRemoteZ_Base::FinishConfig(const TRemoteInfo &ri, lc_callback cb,
                                void *cb_arg, uint32_t cb_stage)
{
    return 0;
}

int CRemoteZ_Base::GetTime(const TRemoteInfo &ri, THarmonyTime &ht)
{
    int err = 0;
    if ((err = Write(TYPE_REQUEST, COMMAND_GET_CURRENT_TIME))) {
        debug("Failed to write to remote");
        return LC_ERROR_WRITE;
    }
    uint8_t time[USBNET_REPLY_ROOM];
    unsigned int len;
    uint8_t status;
    if ((err = Read(status, len, time))) {
        debug("Failed to read to remote");
        return LC_ERROR_READ;
    }

    if (time[1] != TYPE_RESPONSE || time[2] != COMMAND_GET_CURRENT_TIME) {
        debug("Incorrect response type from Get Time");
        return LC_ERROR_INVALID_DATA_FROM_REMOTE;
    }

    CRemoteZ_Base::TParamList pl;
    ParseParams(len, time, pl);

    ht.year = GetWord(pl.p[0]);
    ht.month = *pl.p[1];
    ht.day = *pl.p[2];
    ht.hour = *pl.p[3];
    ht.minute = *pl.p[4];
    ht.second = *pl.p[5];
    ht.dow = *pl.p[6]&7;
    ht.utc_offset = static_cast<int16_t>(GetWord(pl.p[7]));
    if (pl.count > 11) {
        ht.timezone = reinterpret_cast<char*>(pl.p[11]);
    } else {
        ht.timezone = "";
    }

    return 0;
}

int CRemoteZ_Base::SetTime(const TRemoteInfo &ri, const THarmonyTime &ht,
                           lc_callback cb, void *cb_arg, uint32_t cb_stage)
{
    int err = 0;

    uint8_t tsv[16] = { static_cast<uint8_t>(ht.year), 0, // 2 bytes
        static_cast<uint8_t>(ht.month),
        static_cast<uint8_t>(ht.day),
        static_cast<uint8_t>(ht.hour),
        static_cast<uint8_t>(ht.minute),
        static_cast<uint8_t>(ht.second),
        static_cast<uint8_t>(ht.dow),
        // utcOffset
        static_cast<uint8_t>(ht.utc_offset), 0, // 2 bytes
        // 0s
        0, 0, // 2 bytes
        0, 0, // 2 bytes
        0, 0, // 2 bytes
        // ht.timezone.c_str()
        };

    if ((err = Write(TYPE_REQUEST, COMMAND_UPDATE_TIME, 16, tsv))) {
        debug("Failed to write to remote");
        return LC_ERROR_WRITE;
    }

    uint8_t rsp[USBNET_REPLY_ROOM];
    unsigned int len;
    uint8_t status;
    if ((err = Read(status, len, rsp))) {
        debug("failed to read from remote");
        return LC_ERROR_READ;
    }

    if (rsp[1] != TYPE_RESPONSE || rsp[2] != COMMAND_UPDATE_TIME) {
            return LC_ERROR;
    }

    return 0;
}

int CRemoteZ_HID::TCPSendAndCheck(uint8_t cmd, uint32_t len, uint8_t *data,
                                  bool ackonly)
{
    int err = 0;
    uint8_t status;
    unsigned int rlen;
    uint8_t rsp[USBNET_REPLY_ROOM];

    if ((err = TCP_Write(TYPE_REQUEST, cmd, len, data))) {
        debug("Failed to send request %02X", cmd);
        return LC_ERROR_WRITE;
    }

    if ((err = TCP_Read(status, rlen, rsp))) {
        debug("Failed to read from remote");
        return LC_ERROR_READ;
    }

    /* make sure it was the response we expected */
    if (rsp[0] != TYPE_TCP_ACK) {
        debug("Packet wasn't an ACK!");
        return LC_ERROR;
    }
    if (!ackonly) {
        if (rsp[3] != TYPE_RESPONSE) {
            debug("Packet didn't have response bit!");
            return LC_ERROR;
        }
        if (rsp[4] != cmd) {
            debug("The cmd bit didn't match our request packet");
            return LC_ERROR;
        }
    }

    return 0;
}

int CRemoteZ_HID::UpdateConfig(const uint32_t len, const uint8_t *wr,
                               lc_callback cb, void *cb_arg, uint32_t cb_stage,
                               uint32_t xml_size, uint8_t *xml)
{
    int err = 0;
    int cb_count = 0;

    cb(LC_CB_STAGE_INITIALIZE_UPDATE, cb_count++, 0, 4,
       LC_CB_COUNTER_TYPE_STEPS, cb_arg, NULL);
    /* Start a TCP transfer */
    if ((err = Write(TYPE_REQUEST, COMMAND_INITIATE_UPDATE_TCP_CHANNEL))) {
        debug("Failed to write to remote");
        return LC_ERROR_WRITE;
    }

    uint8_t rsp[USBNET_REPLY_ROOM];
    unsigned int rlen;
    uint8_t status;

    /* Make sure the remote is ready to start the TCP transfer */
    if ((err = Read(status, rlen, rsp))) {
        debug("Failed to read from remote");
        return LC_ERROR_READ;
    }

    if (rsp[1] != TYPE_RESPONSE || rsp[2] !=
        COMMAND_INITIATE_UPDATE_TCP_CHANNEL) {
        return LC_ERROR;
    }
    cb(LC_CB_STAGE_INITIALIZE_UPDATE, cb_count++, 1, 4,
       LC_CB_COUNTER_TYPE_STEPS, cb_arg, NULL);

    /* Look for a SYN packet */
    debug("Looking for syn");
    if ((err = TCP_Read(status, rlen, rsp))) {
        debug("Failed to read syn from remote");
        return LC_ERROR_READ;
    }

    if (rsp[0] != TYPE_TCP_SYN) {
        debug("Not a SYN packet!");
        return LC_ERROR;
    }
    cb(LC_CB_STAGE_INITIALIZE_UPDATE, cb_count++, 2, 4,
       LC_CB_COUNTER_TYPE_STEPS, cb_arg, NULL);

    /* ACK it with a command to start an update */
    debug("START_UPDATE");
    uint8_t cmd[60] = { 0x00, 0x04 };
    if ((err = TCP_Write(TYPE_REQUEST, COMMAND_START_UPDATE, 2, cmd))) {
        debug("Failed to write start-update to remote");
        return LC_ERROR_WRITE;
    }

    if ((err = TCP_Read(status, rlen, rsp))) {
        debug("Failed to read from remote");
        return LC_ERROR_READ;
    }

    /* make sure ot says 'start update response' */
    if (rsp[0] != TYPE_TCP_ACK || rsp[3] != TYPE_RESPONSE ||
        rsp[4] != COMMAND_START_UPDATE) {
        debug("Not expected ack");
        return LC_ERROR;
    }
    cb(LC_CB_STAGE_INITIALIZE_UPDATE, cb_count++, 3, 4,
       LC_CB_COUNTER_TYPE_STEPS, cb_arg, NULL);

    /* write update-header */
    debug("UPDATE_HEADER");
    uint32_t nlen = len;
    unsigned char *size_ptr = (unsigned char *)&nlen;
    for (int i = 0; i < 4; i++) {
        cmd[i] = size_ptr[i];
    }
    cmd[4] = 0x04;
    if ((err = TCPSendAndCheck(COMMAND_WRITE_UPDATE_HEADER, 5, cmd))) {
        return err;
    }
    cb(LC_CB_STAGE_INITIALIZE_UPDATE, cb_count++, 4, 4,
       LC_CB_COUNTER_TYPE_STEPS, cb_arg, NULL);
    cb_count = 0;

    /* write data */
    debug("UPDATE_DATA");
    int pkt_len;
    int tlen = len;
    uint8_t *wr_ptr = const_cast<uint8_t*>(wr);
    while (tlen) {
        pkt_len = 58;
        if (tlen < pkt_len) {
            pkt_len = tlen;
        }
        tlen -= pkt_len;

        debug_packet("DATA %d, sending %d bytes, %d bytes left", cb_count,
              pkt_len, tlen);

        if ((err = TCPSendAndCheck(COMMAND_WRITE_UPDATE_DATA, pkt_len,
            wr_ptr, true))) {
            return err;
        }
        wr_ptr += pkt_len;

        if (cb) {
            cb(LC_CB_STAGE_WRITE_CONFIG, cb_count++, (int)(wr_ptr - wr), len,
               LC_CB_COUNTER_TYPE_BYTES, cb_arg, NULL);
        }
    }

    /* write update-done */
    cb_count = 0;
    cb(LC_CB_STAGE_FINALIZE_UPDATE, cb_count++, 0, 6, LC_CB_COUNTER_TYPE_STEPS,
       cb_arg, NULL);
    debug("UPDATE_DATA_DONE");
    if ((err = TCPSendAndCheck(COMMAND_WRITE_UPDATE_DATA_DONE))) {
        return err;
    }
    cb(LC_CB_STAGE_FINALIZE_UPDATE, cb_count++, 1, 6, LC_CB_COUNTER_TYPE_STEPS,
       cb_arg, NULL);

    /* Funky ACK exchange - part 1 */
    debug("FUNKY-ACK");
    if ((err = TCP_Ack(false, false))) {
        debug("Failed to send funky-ack");
        return LC_ERROR_WRITE;
    }

    if ((err = TCP_Read(status, rlen, rsp))) {
        debug("Failed to read from remote");
        return LC_ERROR_READ;
    }

    /* Funky ACK exchange - part 2 */
    debug("FUNKY-ACK");
    if ((err = TCP_Ack(false, false))) {
        debug("Failed to send funky-ack");
        return LC_ERROR_WRITE;
    }

    if ((err = TCP_Read(status, rlen, rsp))) {
        debug("Failed to read from remote");
        return LC_ERROR_READ;
    }
    cb(LC_CB_STAGE_FINALIZE_UPDATE, cb_count++, 2, 6, LC_CB_COUNTER_TYPE_STEPS,
       cb_arg, NULL);

    /* send get-cheksum */
    debug("GET_CHECKSUM");
    cmd[0] = 0xFF;
    cmd[1] = 0xFF;
    cmd[2] = 0x04;
    if ((err = TCPSendAndCheck(COMMAND_GET_UPDATE_CHECKSUM, 3, cmd))) {
        return err;
    }
    cb(LC_CB_STAGE_FINALIZE_UPDATE, cb_count++, 3, 6, LC_CB_COUNTER_TYPE_STEPS,
       cb_arg, NULL);

    /* send finish-update */
    debug("FINISH_UPDATE");
    cmd[0] = 0x01;
    cmd[1] = 0x04;
    /*
     * OK, this is a bit weird. We will eventually get a response to the
     * FINISH_UPDATE, but first we get an "empty" ack, do another funky-ack
     * exchange, and then we'll get the real response to this FINISH_UPDATE.
     */
    if ((err = TCPSendAndCheck(COMMAND_FINISH_UPDATE, 2, cmd, true))) {
        return err;
    }
    cb(LC_CB_STAGE_FINALIZE_UPDATE, cb_count++, 4, 6, LC_CB_COUNTER_TYPE_STEPS,
       cb_arg, NULL);

    /* Funky ACK exchange */
    debug("FUNKY-ACK");
    if ((err = TCP_Ack(false, false))) {
        debug("Failed to send funky-ack");
        return LC_ERROR_WRITE;
    }

    /* Read their empty ack */
    if ((err = TCP_Read(status, rlen, rsp))) {
        debug("Failed to read from remote");
        return LC_ERROR_READ;
    }
    if (rsp[0] != TYPE_TCP_ACK) {
        debug("Failed to read ack");
        return LC_ERROR;
    }

    /* And then we should have the response we want. */
    if ((err = TCP_Read(status, rlen, rsp))) {
        debug("Failed to read from remote");
        return LC_ERROR_READ;
    }

    /* make sure we got an ack */
    if (rsp[0] != TYPE_TCP_ACK || rsp[3] != TYPE_RESPONSE ||
        rsp[4] != COMMAND_FINISH_UPDATE) {
        debug("Failed to read finish-update ack");
        return LC_ERROR;
    }
    cb(LC_CB_STAGE_FINALIZE_UPDATE, cb_count++, 5, 6, LC_CB_COUNTER_TYPE_STEPS,
       cb_arg, NULL);

    /* FIN-ACK */
    debug("FIN-ACK");
    if ((err = TCP_Ack(false, true))) {
        debug("Failed to send fin-ack");
        return LC_ERROR_WRITE;
    }

    if ((err = TCP_Read(status, rlen, rsp))) {
        debug("Failed to read from remote");
        return LC_ERROR_READ;
    }

    /* Make sure we got an ack */
    if (rsp[0] != (TYPE_TCP_ACK | TYPE_TCP_FIN)) {
        debug("Failed to read finish-update ack");
        return LC_ERROR;
    }

    if ((err = TCP_Ack(true, false))) {
        debug("Failed to ack the ack of our fin-ack");
        return LC_ERROR_WRITE;
    }
    cb(LC_CB_STAGE_FINALIZE_UPDATE, cb_count++, 6, 6, LC_CB_COUNTER_TYPE_STEPS,
       cb_arg, NULL);

    /*
     * Official traces seem to show a final ack to the above ack, but for us
     * it never comes... so we don't bother trying to read it.
     */

    /* Return TCP state to initial conditions */
    SYN_ACKED = false;

    return 0;
}

int CRemoteZ_HID::LearnIR(uint32_t *freq, uint32_t **ir_signal,
                          uint32_t *ir_signal_length, lc_callback cb,
                          void *cb_arg, uint32_t cb_stage)
{
    return LC_ERROR_UNSUPP;
}

int CRemoteZ_Base::ReadFile(const char *filename, uint8_t *rd,
                            const uint32_t rdlen, uint32_t *data_read,
                            uint8_t start_seq, lc_callback cb, void *cb_arg,
                            uint32_t cb_stage)
{
    return LC_ERROR_UNSUPP;
}

int CRemoteZ_Base::WriteFile(const char *filename, uint8_t *wr,
                             const uint32_t wrlen)
{
    return LC_ERROR_UNSUPP;
}
