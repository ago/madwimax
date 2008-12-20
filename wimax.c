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

#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

#include <libusb-1.0/libusb.h>

#include "protocol.h"
#include "wimax.h"
#include "tun_dev.h"

#define DEVICE_VID		0x04e9
#define DEVICE_PID		0x6761

#define EP_IN			(2 | LIBUSB_ENDPOINT_IN)
#define EP_OUT			(4 | LIBUSB_ENDPOINT_OUT)

#define MAX_PACKET_LEN		0x4000

static struct libusb_device_handle *devh = NULL;
static struct libusb_transfer *req_transfer = NULL;

static unsigned char read_buffer[MAX_PACKET_LEN];
static int req_in_progress = 0;

static int tap_fd = -1;
static char tap_dev[20];

static struct wimax_dev_status wd_status;
static int wimax_debug_level = 0;

static nfds_t nfds;
static struct pollfd* fds = NULL;

char *wimax_states[] = {"INIT", "SYNC", "NEGO", "NORMAL", "SLEEP", "IDLE", "HHO", "FBSS", "RESET", "RESERVED", "UNDEFINED", "BE", "NRTPS", "RTPS", "ERTPS", "UGS", "INITIAL_RNG", "BASIC", "PRIMARY", "SECONDARY", "MULTICAST", "NORMAL_MULTICAST", "SLEEP_MULTICAST", "IDLE_MULTICAST", "FRAG_BROADCAST", "BROADCAST", "MANAGEMENT", "TRANSPORT"};

static void exit_release_resources(int code);

static int find_wimax_device(void)
{
	devh = libusb_open_device_with_vid_pid(NULL, DEVICE_VID, DEVICE_PID);
	return devh ? 0 : -EIO;
}

/* print debug message. */
void debug_msg(int level, const char *fmt, ...)
{
	va_list va;

	if (level > wimax_debug_level) return;

	va_start(va, fmt);
	vprintf(fmt, va);
	va_end(va);
}

/* If a character is not printable, return a dot. */
#define toprint(x) (isprint((unsigned int)x) ? (x) : '.')

/* dump message msg and len bytes from buf in hexadecimal and ASCII. */
void debug_dumphexasc(int level, const char *msg, const void *buf, int len)
{
	int i;

	if (level > wimax_debug_level) return;

	printf("%s\n", msg);
	for (i = 0; i < len; i+=16) {
		int j;
		char hex[49];
		char ascii[17];
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
		debug_msg(0, "bulk read error %d\n", r);
		return r;
	}

	debug_dumphexasc(1, "Bulk read:", data, transferred);
	return r;
}

static int set_data(unsigned char* data, int size)
{
	int r;
	int transferred;

	debug_dumphexasc(1, "Bulk write:", data, size);

	r = libusb_bulk_transfer(devh, EP_OUT, data, size, &transferred, 0);
	if (r < 0) {
		debug_msg(0, "bulk write error %d\n", r);
		return r;
	}
	if (transferred < size) {
		debug_msg(0, "short write (%d)\n", r);
		return -1;
	}
	return r;
}

static void cb_req(struct libusb_transfer *transfer)
{
	req_in_progress = 0;
	if (transfer->status != LIBUSB_TRANSFER_COMPLETED) {
		debug_msg(0, "req transfer status %d?\n", transfer->status);
		return;
	}

	debug_dumphexasc(1, "Async read:", transfer->buffer, transfer->actual_length);
	process_response(&wd_status, transfer->buffer, transfer->actual_length);
	if (libusb_submit_transfer(req_transfer) < 0) {
		debug_msg(0, "async read transfer sumbit failed\n");
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

int write_netif(const void *buf, int count)
{
	return tap_write(tap_fd, buf, count);
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

	debug_msg(0, "Continuous async read start...\n");
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

	debug_msg(0, "Chip info: %s\n", wd_status.chip);
	debug_msg(0, "Firmware info: %s\n", wd_status.firmware);

	req_in_progress = 1;
	len = fill_init1_req(req_data, MAX_PACKET_LEN);
	r = set_data(req_data, len);
	if (r < 0) {
		return r;
	}

	len = fill_mac_req(req_data, MAX_PACKET_LEN);
	r = set_data(req_data, len);
	if (r < 0) {
		return r;
	}

	while (req_in_progress) {
		r = libusb_handle_events(NULL);
		if (r < 0)
			return r;
	}

	debug_msg(0, "MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", wd_status.mac[0], wd_status.mac[1], wd_status.mac[2], wd_status.mac[3], wd_status.mac[4], wd_status.mac[5]);

	req_in_progress = 1;
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

	req_in_progress = 1;
	len = fill_init2_req(req_data, MAX_PACKET_LEN);
	r = set_data(req_data, len);
	if (r < 0) {
		return r;
	}

	while (req_in_progress) {
		r = libusb_handle_events(NULL);
		if (r < 0)
			return r;
	}

	req_in_progress = 1;
	len = fill_init3_req(req_data, MAX_PACKET_LEN);
	r = set_data(req_data, len);
	if (r < 0) {
		return r;
	}

	while (req_in_progress) {
		r = libusb_handle_events(NULL);
		if (r < 0)
			return r;
	}

	req_in_progress = 1;
	len = fill_authorization_data_req(req_data, MAX_PACKET_LEN);
	r = set_data(req_data, len);
	if (r < 0) {
		return r;
	}

	return 0;
}

static int read_tap()
{
	unsigned char buf[MAX_PACKET_LEN];
	int hlen = get_D_header_len();
	int r;
	int len;

	r = tap_read(tap_fd, buf + hlen, MAX_PACKET_LEN - hlen);

	if (r < 0)
	{
		debug_msg(0, "Error while reading from TAP interface\n");
		return r;
	}

	if (r == 0)
	{
		return 0;
	}

	len = fill_outgoing_packet_header(buf, MAX_PACKET_LEN, r);
	debug_dumphexasc(1, "Outgoing packet:", buf, len);
	r = set_data(buf, len);

	return r;
}

static int process_events(int timeout)
{
	struct timeval tv;
	int r;
	int libusb_delay;
	int delay;
	int i;
	char process_libusb = 0;

	r = libusb_get_next_timeout(NULL, &tv);
	if (r == 1 && tv.tv_sec == 0 && tv.tv_usec == 0)
	{
		r = libusb_handle_events(NULL);
	}

	delay = libusb_delay = tv.tv_sec * 1000 + tv.tv_usec;
	if (delay == 0 || delay > timeout)
	{
		delay = timeout;
	}

	r = poll(fds, nfds, delay);
	if (r < 0)
	{
		return r;
	}

	process_libusb = (r == 0 && delay == libusb_delay);

	if (fds[nfds - 1].revents)
	{
		r = read_tap();
		if (r < 0)
		{
			return r;
		}
	}

	for (i = 0; i < nfds - 1 && !process_libusb; ++i)
	{
		process_libusb |= fds[i].revents;
	}

	if (process_libusb)
	{
		r = libusb_handle_events(NULL);
		if (r < 0)
		{
			return r;
		}
	}

	return 0;
}

/* handle events until timeout is reached or one of the events in event_mask happen */
static int process_events_by_mask(int timeout, int event_mask)
{
	struct timeval start, curr;
	int r;
	int delay = timeout;

	r = gettimeofday(&start, NULL);
	if (r < 0)
		return r;

	while ((wd_status.info_updated & event_mask) == 0 && delay >= 0) {
		long a;

		r = process_events(delay);
		if (r < 0)
			return r;

		r = gettimeofday(&curr, NULL);
		if (r < 0)
			return r;

		a = (curr.tv_sec - start.tv_sec) * 1000 + (curr.tv_usec - start.tv_usec) / 1000;
		delay = timeout - a;
	}

	return delay;
}

int alloc_fds()
{
	int i;
	const struct libusb_pollfd **usb_fds = libusb_get_pollfds(NULL);

	if (!usb_fds)
	{
		return -1;
	}

	nfds = 0;
	while (usb_fds[nfds])
	{
		nfds++;
	}
	nfds++;

	if(fds != NULL) {
		free(fds);
	}

	fds = (struct pollfd*)calloc(nfds, sizeof(struct pollfd));
	for (i = 0; usb_fds[i]; ++i)
	{
		fds[i].fd = usb_fds[i]->fd;
		fds[i].events = usb_fds[i]->events;
	}
	fds[nfds - 1].fd = tap_fd;
	fds[nfds - 1].events = POLLIN;
	fds[nfds - 1].revents = 0;

	free(usb_fds);

	return 0;
}

void cb_added_pollfd(int fd, short events, void *user_data)
{
	alloc_fds();
}

void cb_removed_pollfd(int fd, void *user_data)
{
	alloc_fds();
}

static int flag = 0;

static int scan_loop(void)
{
	unsigned char req_data[MAX_PACKET_LEN];
	int len;
	int r;

	alloc_fds();
	libusb_set_pollfd_notifiers(NULL, cb_added_pollfd, cb_removed_pollfd, NULL);

	while (1)
	{
		if (wd_status.net_found == 0) {
			wd_status.info_updated = 0;
			len = fill_find_network_req(req_data, MAX_PACKET_LEN, 1);
			r = set_data(req_data, len);
			if (r < 0) {
				return r;
			}

			process_events_by_mask(5000, WDS_NET_FOUND);

			if (wd_status.net_found == 0) {
				debug_msg(0, "Network not found.\n");
			} else {
				debug_msg(0, "Network found.\n");
			}
		} else {
			wd_status.info_updated = 0;
			//len = fill_connection_params1_req(req_data, MAX_PACKET_LEN);
			//r = set_data(req_data, len);
			//if (r < 0) {
			//	return r;
			//}

			len = fill_connection_params2_req(req_data, MAX_PACKET_LEN);
			r = set_data(req_data, len);
			if (r < 0) {
				return r;
			}

			process_events_by_mask(500, WDS_RSSI | WDS_CINR | WDS_TXPWR | WDS_FREQ | WDS_BSID);

			debug_msg(0, "RSSI: %d   CINR: %f   TX Power: %d   Frequency: %d\n", wd_status.rssi, wd_status.cinr, wd_status.txpwr, wd_status.freq);
			debug_msg(0, "BSID: %02x:%02x:%02x:%02x:%02x:%02x\n", wd_status.bsid[0], wd_status.bsid[1], wd_status.bsid[2], wd_status.bsid[3], wd_status.bsid[4], wd_status.bsid[5]);

			wd_status.info_updated = 0;
			len = fill_state_req(req_data, MAX_PACKET_LEN);
			r = set_data(req_data, len);
			if (r < 0) {
				return r;
			}

			process_events_by_mask(500, WDS_STATE);

			debug_msg(0, "State: %s   Number: %d   Response: %d\n", wimax_states[wd_status.state], wd_status.state, wd_status.net_found);

			if (flag == 0 && wd_status.net_found == 1) {
				flag = 1;
				wd_status.info_updated = 0;
				len = fill_find_network_req(req_data, MAX_PACKET_LEN, 2);
				r = set_data(req_data, len);
				if (r < 0) {
					return r;
				}
			}

			process_events_by_mask(5000, WDS_NET_FOUND);
		}
		if (wd_status.net_found != 1)
		{
			flag = 0;
		}
	}
}

static int parse_args(int argc, char **argv)
{
	return 0;
}

static void exit_close_usb(int code);

static void exit_release_resources(int code)
{
	if(req_transfer != NULL) {
		libusb_cancel_transfer(req_transfer);
		libusb_free_transfer(req_transfer);
	}
	if(tap_fd >= 0) {
		tap_close(tap_fd, tap_dev);
	}
	libusb_set_pollfd_notifiers(NULL, NULL, NULL, NULL);
	if(fds != NULL) {
		free(fds);
	}
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

int main(int argc, char **argv)
{
	struct sigaction sigact;
	int r = 1;

	parse_args(argc, argv);

	r = libusb_init(NULL);
	if (r < 0) {
		debug_msg(0, "failed to initialise libusb\n");
		exit(1);
	}

	r = find_wimax_device();
	if (r < 0) {
		debug_msg(0, "Could not find/open device\n");
		exit_close_usb(1);
	}

	r = libusb_claim_interface(devh, 0);
	if (r < 0) {
		debug_msg(0, "usb_claim_interface error %d\n", r);
		exit_close_usb(1);
	}
	debug_msg(0, "claimed interface\n");

	sigact.sa_handler = sighandler;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = 0;
	sigaction(SIGINT, &sigact, NULL);
	sigaction(SIGTERM, &sigact, NULL);
	sigaction(SIGQUIT, &sigact, NULL);

	r = init();
	if (r < 0) {
		debug_msg(0, "init error %d\n", r);
		exit_release_resources(1);
	}

	tap_fd = tap_open(tap_dev);
	if (tap_fd < 0) {
		debug_msg(0, "failed to allocate tap interface\n");
		exit_release_resources(1);
	}
	tap_set_hwaddr(tap_fd, tap_dev, wd_status.mac);

	debug_msg(0, "Allocated tap interface: %s\n", tap_dev);

	r = scan_loop();
	if (r < 0) {
		debug_msg(0, "scan_loop error %d\n", r);
		exit_release_resources(1);
	}

	exit_release_resources(0);
	return 0;
}

