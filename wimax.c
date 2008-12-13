/*
 * This is a proof-of-concept driver for Samsung SWC-U200 wimax dongle.
 * Copyright (C) 2008 Alexander Gordeev <lasaine@lvk.cs.msu.su>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <libusb-1.0/libusb.h>

#include "protocol.h"
#include "wimax.h"

#define DEVICE_VID		0x04e9
#define DEVICE_PID		0x6761

#define EP_IN			(2 | LIBUSB_ENDPOINT_IN)
#define EP_OUT			(4 | LIBUSB_ENDPOINT_OUT)

#define MAX_PACKET_LEN		0x4000

static struct libusb_device_handle *devh = NULL;
static unsigned char read_buffer[MAX_PACKET_LEN];
static struct libusb_transfer *req_transfer = NULL;
static int req_in_progress = 0;

struct wimax_dev_status wd_status;


static void exit_release_resources(int code);

static int find_wimax_device(void)
{
	devh = libusb_open_device_with_vid_pid(NULL, DEVICE_VID, DEVICE_PID);
	return devh ? 0 : -EIO;
}

/* If a character is not printable, return a dot. */
#define toprint(x) (isprint((unsigned int)x) ? (x) : '.')

/* dump message msg and len bytes from buf in hexadecimal and ASCII. */
static void dump_hex_ascii(const char *msg, const void *buf, int len)
{
	int i;
	printf("%s\n", msg);
	for (i = 0; i < len; i+=16) {
		int j;
		unsigned char hex[49];
		unsigned char ascii[17];
		memset(hex, ' ', 48);
		for(j = i; j < i + 16 && j < len; j++) {
			sprintf(hex + ((j - i) * 3), " %02x", ((unsigned char*)buf)[j]);
			ascii[j - i] = toprint(((unsigned char*)buf)[j]);
		}
		hex[(j - i) * 3] = ' ';
		hex[48] = 0;
		ascii[j - i] = 0;
		printf("  %08x:%s    %s\n", i, hex, ascii);
	}
}

static int get_data(unsigned char* data, int size)
{
	int r;
	int transferred;

	r = libusb_bulk_transfer(devh, EP_IN, data, size, &transferred, 0);
	if (r < 0) {
		fprintf(stderr, "bulk read error %d\n", r);
		return r;
	}

	dump_hex_ascii("Bulk read:", data, transferred);
	return r;
}

static int set_data(unsigned char* data, int size)
{
	int r;
	int transferred;

	dump_hex_ascii("Bulk write:", data, size);

	r = libusb_bulk_transfer(devh, EP_OUT, data, size, &transferred, 0);
	if (r < 0) {
		fprintf(stderr, "bulk write error %d\n", r);
		return r;
	}
	if (transferred < size) {
		fprintf(stderr, "short write (%d)\n", r);
		return -1;
	}
	return r;
}

static void cb_req(struct libusb_transfer *transfer)
{
	req_in_progress = 0;
	if (transfer->status != LIBUSB_TRANSFER_COMPLETED) {
		fprintf(stderr, "req transfer status %d?\n", transfer->status);
		return;
	}

	dump_hex_ascii("Async read:", transfer->buffer, transfer->actual_length);
	process_response(&wd_status, transfer->buffer, transfer->actual_length);
	if (libusb_submit_transfer(req_transfer) < 0) {
		fprintf(stderr, "async read transfer sumbit failed\n");
	}
}

static int alloc_transfers(void)
{
	req_transfer = libusb_alloc_transfer(0);
	if (!req_transfer)
		return -ENOMEM;
	
	libusb_fill_bulk_transfer(req_transfer, devh, EP_IN, read_buffer,
		sizeof(read_buffer), cb_req, NULL, 0);

	return 0;
}

static int init(void)
{
	unsigned char data1[] = {0x57, 0x45, 0x04, 0x00, 0x00, 0x02, 0x00, 0x74};
	unsigned char data2[] = {0x57, 0x50, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	unsigned char data3[] = {0x57, 0x43, 0x12, 0x00, 0x15, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x04, 0x50, 0x04, 0x00, 0x00};
	unsigned char req_data[MAX_PACKET_LEN];
	int len;
	int r;

	r = set_data(data1, sizeof(data1));
	if (r < 0) {
		return r;
	}

	r = get_data(read_buffer, sizeof(read_buffer));
	if (r < 0) {
		return r;
	}

	r = set_data(data2, sizeof(data2));
	if (r < 0) {
		return r;
	}

	r = get_data(read_buffer, sizeof(read_buffer));
	if (r < 0) {
		return r;
	}

	alloc_transfers();

	printf("Continuous async read start...\n");
	r = libusb_submit_transfer(req_transfer);
	if (r < 0)
		return r;
	req_in_progress = 1;

	r = set_data(data3, sizeof(data3));
	if (r < 0) {
		return r;
	}

	len = fill_string_info_req(req_data, MAX_PACKET_LEN);
	r = set_data(req_data, len);
	if (r < 0) {
		return r;
	}

	while (req_in_progress) {
		r = libusb_handle_events(NULL);
		if (r < 0)
			return r;
	}

	return 0;
}

static void exit_close_usb(int code);

static void exit_release_resources(int code)
{
	if(req_transfer != NULL)
		libusb_free_transfer(req_transfer);
	libusb_release_interface(devh, 0);
	exit_close_usb(code);
}

static void exit_close_usb(int code)
{
	libusb_close(devh);
	libusb_exit(NULL);
	exit(code);
}

static void sighandler(int signum) {
	exit_release_resources(0);
}

int main(void)
{
	struct sigaction sigact;
	int r = 1;

	r = libusb_init(NULL);
	if (r < 0) {
		fprintf(stderr, "failed to initialise libusb\n");
		exit(1);
	}

	r = find_wimax_device();
	if (r < 0) {
		fprintf(stderr, "Could not find/open device\n");
		exit_close_usb(1);
	}

	r = libusb_claim_interface(devh, 0);
	if (r < 0) {
		fprintf(stderr, "usb_claim_interface error %d\n", r);
		exit_close_usb(1);
	}
	printf("claimed interface\n");

	sigact.sa_handler = sighandler;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = 0;
	sigaction(SIGINT, &sigact, NULL);
	sigaction(SIGTERM, &sigact, NULL);
	sigaction(SIGQUIT, &sigact, NULL);

	init();

	exit_release_resources(0);
}

