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
#ifdef _WIN32
#include <setupapi.h>
#include <cfgmgr32.h>
#elif defined(HAVE_USBNET_LINK)
#include <libusb.h>
#endif

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
#if defined(HID_API_MAKE_VERSION) && \
    HID_API_VERSION >= HID_API_MAKE_VERSION(0, 15, 0)
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

/*
 * Some remotes take requests only in the moment after they are plugged in
 * (a Monster-branded 880). These bring that moment back without a hand on
 * the cable, where the system lets an ordinary user: libusb's port reset on
 * Linux and macOS, and on Windows an eject - what "Safely Remove" does - and
 * a fresh look for hardware, which an ordinary user may ask for.
 */
#ifdef _WIN32
int HID_ResetRemote()
{
    HDEVINFO set = SetupDiGetClassDevsA(NULL, "USB", NULL,
                                        DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (set == INVALID_HANDLE_VALUE) {
        debug("Could not list USB devices: %lu", GetLastError());
        return LC_ERROR_OS;
    }
    SP_DEVINFO_DATA info;
    info.cbSize = sizeof(info);
    DEVINST remote = 0;
    char id[MAX_DEVICE_ID_LEN];
    for (DWORD i = 0; SetupDiEnumDeviceInfo(set, i, &info); i++) {
        unsigned int vid, pid;
        if (SetupDiGetDeviceInstanceIdA(set, &info, id, sizeof(id), NULL)
            && sscanf(id, "USB\\VID_%4x&PID_%4x", &vid, &pid) == 2
            && is_harmony_ids(vid, pid) && pid != 0xC11F) {
            remote = info.DevInst;
            break;
        }
    }
    SetupDiDestroyDeviceInfoList(set);
    if (!remote) {
        debug("No Harmony among the USB devices");
        return LC_ERROR_CONNECT;
    }

    DEVINST parent;
    if (CM_Get_Parent(&parent, remote, 0) != CR_SUCCESS)
        parent = 0;
    PNP_VETO_TYPE veto = PNP_VetoTypeUnknown;
    char vetoer[MAX_PATH] = "";
    CONFIGRET cr = CM_Request_Device_EjectA(remote, &veto, vetoer,
                                            sizeof(vetoer), 0);
    if (cr != CR_SUCCESS || veto != PNP_VetoTypeUnknown) {
        debug("Windows did not let the remote go: %lu, veto %d by %s",
              (unsigned long)cr, (int)veto, vetoer);
        return LC_ERROR_OS;
    }
    Sleep(500);
    if (!parent) {
        debug("Ejected the remote; no hub to look on again");
        return 0;
    }
    cr = CM_Reenumerate_DevNode(parent, CM_REENUMERATE_SYNCHRONOUS);
    debug("Ejected the remote and asked Windows to look again: %lu",
          (unsigned long)cr);
    return 0;
}
#elif defined(HAVE_USBNET_LINK)
int HID_ResetRemote()
{
    libusb_context *ctx;
    if (libusb_init(&ctx)) {
        debug("libusb would not start");
        return LC_ERROR_OS;
    }
    libusb_device **list;
    ssize_t n = libusb_get_device_list(ctx, &list);
    int err = LC_ERROR_CONNECT;
    for (ssize_t i = 0; i < n; i++) {
        struct libusb_device_descriptor d;
        // not the USB network remotes (900, 1000, 1100), which are no HID
        if (libusb_get_device_descriptor(list[i], &d)
            || !is_harmony_ids(d.idVendor, d.idProduct) || d.idProduct == 0xC11F)
            continue;
        libusb_device_handle *handle;
        int r = libusb_open(list[i], &handle);
        if (r) {
            debug("Could not open the remote to reset it: %s",
                  libusb_error_name(r));
            err = LC_ERROR_OS;
            break;
        }
        r = libusb_reset_device(handle);
        // NOT_FOUND: it came back as a new device, which is the point.
        debug("USB reset of the remote: %s",
              r ? libusb_error_name(r) : "done");
        libusb_close(handle);
        err = (r == 0 || r == LIBUSB_ERROR_NOT_FOUND) ? 0 : LC_ERROR_OS;
        break;
    }
    if (n >= 0)
        libusb_free_device_list(list, 1);
    libusb_exit(ctx);
    if (err == LC_ERROR_CONNECT)
        debug("No Harmony on USB to reset");
    return err;
}
#else
int HID_ResetRemote()
{
    return LC_ERROR_UNSUPP;
}
#endif

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
