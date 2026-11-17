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
 * (C) Copyright Phil Dibowitz 2007
 */

#include "lc_internal.h"
#include "libconcord.h"

#ifdef WANT_HIDAPI
#ifndef LC_LIBHIDAPI
#define LC_LIBHIDAPI

#include "hid.h"
#include <hidapi/hidapi.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/*
 * Harmonies either fall under logitech's VendorID (0x046d), and logitech's
 * productID range for Harmonies (0xc110 - 0xc14f)...
 *
 * OR, they fall under 0x400/0xc359 (older 7-series, all 6-series).
 */
#define LOGITECH_VID 0x046D
#define LOGITECH_MIN_PID 0xc110
#define LOGITECH_MAX_PID 0xc14f
#define NATIONAL_VID 0x0400
#define NATIONAL_PID 0xc359

#define USB_PACKET_LENGTH 64

hid_device *h_dev;

/*
 * Logitech's client opens a remote twice on Windows, once to read and once to
 * write, and keeps a read waiting on the first from the moment it opens. On
 * Windows we do the same: h_read is a second handle to the same remote, with a
 * read started as soon as it is opened. Elsewhere, and if the second open
 * fails, it is h_dev.
 */
hid_device *h_read;

static bool quiet;

void HID_Quiet(bool on)
{
    quiet = on;
}

int InitUSB()
{
    hid_init();
    /*
     * Note we do NOT call hid_exit() in ShutdownUSB, because you can
     * never reinitialize libhidapi - and on a reset, we need
     * to come back and do more stuff. So we set it up as an atexit()
     */
    atexit((void(*)())hid_exit);
    return 0;
}

void ShutdownUSB()
{
    if (h_read && h_read != h_dev) {
        hid_close(h_read);
    }
    h_read = NULL;
    if (h_dev) {
        hid_close(h_dev);
    }
}

static bool is_harmony_ids(unsigned int vid, unsigned int pid)
{
    /* IF vendor == logitech AND product is in range of harmony
     *   OR vendor == National Semiconductor and product is harmony
     */
    return (vid == LOGITECH_VID
            && pid >= LOGITECH_MIN_PID && pid <= LOGITECH_MAX_PID)
        || (vid == NATIONAL_VID && pid == NATIONAL_PID);
}

bool is_harmony(struct hid_device_info *dev)
{
    return is_harmony_ids(dev->vendor_id, dev->product_id);
}

bool HID_RemotePresent()
{
    hid_init();
    struct hid_device_info *devs = hid_enumerate(0x0, 0x0);
    bool found = false;
    for (struct hid_device_info *cur = devs; cur && !found; cur = cur->next)
        found = is_harmony(cur);
    hid_free_enumeration(devs);
    return found;
}

/*
 * Find a HID device that is a Harmony
 */
int FindRemote(THIDINFO &hid_info)
{
    struct hid_device_info *devs, *cur_dev;
    bool found = false;
    h_read = NULL;
    devs = hid_enumerate(0x0, 0x0);
    cur_dev = devs;
    while (cur_dev) {
        debug("Testing: %04X, %04X", cur_dev->vendor_id, cur_dev->product_id);
        if (is_harmony(cur_dev)) {
            debug("Found a Harmony!");
            hid_info.vid = cur_dev->vendor_id;
            hid_info.pid = cur_dev->product_id;
            hid_info.ver = cur_dev->release_number;
            h_dev = hid_open_path(cur_dev->path);
#ifdef _WIN32
            if (h_dev) {
                h_read = hid_open_path(cur_dev->path);
                if (!h_read) {
                    debug("No second handle for reads, reading on the first");
                }
            }
#endif
            found = true;
            break;
        }
        cur_dev = cur_dev->next;
    }
    hid_free_enumeration(devs);
    if (!found || !h_dev) {
        debug("Failed to establish communication with remote");
        return LC_ERROR_CONNECT;
    }

    if (!h_read) {
        h_read = h_dev;
    } else {
        /*
         * Start the read that stays waiting: hidapi leaves a read that has
         * not completed pending, and the next read picks it up.
         */
        uint8_t early[USB_PACKET_LENGTH];
        int n = hid_read_timeout(h_read, early, USB_PACKET_LENGTH, 0);
        if (n > 0) {
            debug("The remote sent %d bytes before being asked: %02X %02X",
                  n, early[0], early[1]);
        }
    }

    // Fill in hid_info
    const size_t buf_len = 128;
    wchar_t wide_s[buf_len];
    char s[buf_len];
    hid_get_manufacturer_string(h_dev, wide_s, buf_len);
    wcstombs(s, wide_s, buf_len);
    hid_info.mfg = s;
    hid_get_product_string(h_dev, wide_s, buf_len);
    wcstombs(s, wide_s, buf_len);
    hid_info.prod = s;

    return 0;
}

int HID_WriteReport(const uint8_t *data)
{
    uint8_t newdata[USB_PACKET_LENGTH+1];
    newdata[0] = 0x00;
    memcpy(&newdata[1], data, USB_PACKET_LENGTH);
    int err = hid_write(h_dev, newdata, USB_PACKET_LENGTH + 1);
    if (err < 0) {
        if (!quiet)
            debug("Failed to write to device: %d (%ls)", err, hid_error(h_dev));
        return err;
    }

    return 0;
}

int HID_WriteReportControl(const uint8_t *data)
{
#if defined(HID_API_MAKE_VERSION)
#if HID_API_VERSION >= HID_API_MAKE_VERSION(0, 15, 0)
#define LC_HID_OUTPUT_REPORT
#endif
#endif
#ifdef LC_HID_OUTPUT_REPORT
    uint8_t newdata[USB_PACKET_LENGTH+1];
    newdata[0] = 0x00;
    memcpy(&newdata[1], data, USB_PACKET_LENGTH);
    int err = hid_send_output_report(h_dev, newdata, USB_PACKET_LENGTH + 1);
    if (err < 0) {
        debug("No SET_REPORT either: %d (%ls)", err, hid_error(h_dev));
        return err;
    }
    return 0;
#else
    return -1;
#endif
}

int HID_ReadReport(uint8_t *data, unsigned int timeout)
{
    int err = hid_read_timeout(h_read, data, USB_PACKET_LENGTH, timeout);
    if (err < 0) {
        debug("Failed to read from device: %d (%ls)", err, hid_error(h_read));
        return err;
    } else if (err == 0) {
        if (!quiet)
            debug("USB read timed out");
        return 1;
    }

    return 0;
}

#endif
#endif
