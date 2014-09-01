/*
    SPOOL - Socket Pool interface for bulk socket operations

    Copyright (C) 2014  Edward Blizniuk (known also as Ed Blake)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#ifndef _SPOOL_H_
#define _SPOOL_H_

#ifdef _SPOOL_KERNEL
#include <linux/in.h>
#else
#include <netinet/in.h>
#endif

/* Flags used for SPOOL_IO_ADDSOCK ioctl call */
#define SPOOL_FLAG_CLIENT_SOCK			0x0001
#define SPOLL_FLAG_LISTENING_SOCK		0x0002

/* Statuses for 'status' field of 'struct spool_sbd' */
enum
{
	SPOOL_STAT_DISABLED,
	SPOOL_STAT_OK,
	SPOOL_STAT_CONN_CLOSED,   /* connection is closed by peer */
	SPOOL_STAT_READ_ERROR,
	SPOOL_STAT_WRITE_ERROR,
	SPOOL_STAT_NOT_READY      /* non-blocking socket returned EAGIAN */
};

/* Socket Buffer Descriptor.  It is used for bulk read and write operations
   soack_h is the internal SPOOL socket handler which is equal to the Kernel
   address of Kernel socket structure. We don't use the socket file handler
   to avoid look up in file descriptor list  */

struct spool_sbd
{
	long	sock_h;
	char*	buff;    /* pointer to read or write buffer allocated by the user space application */
	size_t	size;    /* size of the buffer */
	int		offset;  /* initially should be zero; updated by the kernel driver when the buffer is written or read partially */
	int		status;  /* the socket is processed only if the status is SPOOL_STAT_OK */

	void*	private; /* can be used by the user space application to associate any custom data with spool_sbd instance */

	/* list of 'struct spool_sbd' structures should be prepared by the user
	 * space application before SPOOL interface call. The structures should be
	 * allocated in the user space */
	struct spool_sbd * next;
};

/* Socket Descriptor. It is used for socket creation and deletion. */

struct spool_sock
{
	long	sock_h;
	int		flags;
	int		backlog;    /* used for listening socket ceration only */

	struct sockaddr_in local;
	struct sockaddr_in remote;

	struct spool_sock* next;
};

/* Accept Descriptor. It is used for bulk accept operations. sock_list is pointer to an array
   of Socket Descriptors. Spool accept function accepts new connections on the listening socket
   until the list is full or until there are no more connections to accept at this moment. */

struct spool_accept
{
	long				listening_sock_h;

	struct spool_sock* 	sock_list; 	/* pointer to a list of_sock structures */
	size_t				size;		/* input - size of the sockets list, output - number of sockets accepted */
};

/* IOCTL functions definition */

#define MY_MACIG 'S'

#define SPOOL_IO_ADDSOCK	_IOWR(MY_MACIG, 1, struct spool_sock)
#define SPOOL_IO_CLOSESOCK	_IOWR(MY_MACIG, 2, struct spool_sock)
#define SPOOL_IO_ACCEPT		_IOWR(MY_MACIG, 3, struct spool_accept)

#endif /* _SPOOL_H_ */
