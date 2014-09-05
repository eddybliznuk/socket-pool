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

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <net/sock.h>
#include <linux/syscalls.h>

#define _SPOOL_DEBUG
#define _SPOOL_KERNEL
#include "spool.h"

MODULE_AUTHOR("Edward Blizniuk");
MODULE_LICENSE("GPL");

//#define _SPOOL_DEBUG

/* Number of buckets in the socket hash table */
#define SPOOL_HASH_SIZE			10000
#define SPOOL_SOCK_FLAGS		O_NONBLOCK

struct sock_list_entry
{
	struct socket*				sock;
	struct sock_list_entry* 	next;
};

struct spool_instance
{
	/* Hash of all sockets opened by the driver instance. Used for instance clean up */
	struct sock_list_entry**	sock_hash;

	/* List of listening sockets for poll implementation. We assume that it is short */
	struct sock_list_entry*		lis_socks;

	struct msghdr 				msg;
	struct iovec 				iov;
	struct spool_sbd  			k_sbd;

	int							sock_flags;
	int 						sock_proto;
};

static unsigned int hash(long val)
{
	unsigned int   	hash = 0;
	unsigned char*	cur = (unsigned char*)&val;
	int  			i;

	for (i=0; i<sizeof(val); ++i)
		hash += (hash^cur[i]) << (i*8);

	return (hash % SPOOL_HASH_SIZE);
}

static void add_to_hash(struct spool_instance* si, struct socket* sock)
{
	unsigned int idx = hash((long)sock);
	struct sock_list_entry*	sle = kmalloc(sizeof(struct sock_list_entry), GFP_KERNEL);

	if(sle == NULL)
	{
		printk(KERN_ERR "SPOOL: Can't allocate memory for socket hash entry\n");
		return;
	}

	sle->sock 			= sock;
	sle->next 			= si->sock_hash[idx];
	si->sock_hash[idx]	= sle;

#ifdef _SPOOL_DEBUG
	printk(KERN_INFO "SPOOL: Added to hash socket [%lx]\n", (long)sock);
#endif
}

static void del_from_hash(struct spool_instance* si, struct socket* sock)
{
	unsigned int idx = hash((long)sock);
	struct sock_list_entry** sle = &si->sock_hash[idx];

	while(*sle != NULL)
	{
		if((*sle)->sock == sock)
		{
			struct sock_list_entry* tmp = *sle;
			*sle = (*sle)->next;
			kfree(tmp);

#ifdef _SPOOL_DEBUG
			printk(KERN_INFO "SPOOL: Deleted from hash socket [%lx]\n", (long)sock);
#endif
			return;
		}

		sle = &((*sle)->next);
	}
}


static void spool_release_resources(void* priv)
{
	int i;
	struct spool_instance* 	si = (struct spool_instance*)priv;
	struct sock_list_entry* sle;

	/* Release all sockets opened in this instance */

	if(si->sock_hash != NULL)
	{
		for (i=0; i<SPOOL_HASH_SIZE; i++)
		{
			while (si->sock_hash[i] != NULL)
			{
				sle = si->sock_hash[i];

	#ifdef _SPOOL_DEBUG
				printk(KERN_INFO "SPOOL: Cleaning up socket [%lx]\n", (long)sle->sock);
	#endif

				/* Here we have to close only the sockets that have no associated file descriptors
				 * The sockets with file descriptors will be closed automatically on instance release
				 * (like all other file descriptors) */
				if(sle->sock && sle->sock->file == NULL)
					sock_release(sle->sock);

				kfree (sle);

				si->sock_hash[i] = si->sock_hash[i]->next;
			}
		}

		kfree(si->sock_hash);
	}
	/* Free socket list entries. We assume that sockets are already released */
	sle = si->lis_socks;

    while (sle != NULL)
    {
    	struct sock_list_entry* tmp = sle;
    	sle = sle->next;

    	kfree(tmp);
    }

	kfree (priv);
}

static int spool_create_sock(struct spool_instance* si, struct socket** sock)
{
	int type, res;

	type	= SOCK_STREAM;

	res = sock_create_kern(PF_INET, type, si->sock_proto, sock);
	if (res < 0) {
		printk(KERN_ERR "SPOOL: Error during socket creation\n");
		return res;
	}

	add_to_hash(si, *sock);

	return res;
}

static int spool_bind_sock(struct socket* sock, struct sockaddr_in* local)
{
#ifdef _SPOOL_DEBUG
	printk(KERN_INFO "SPOOL: Binding socket [%lx] to port [%x] on [%x]\n",
			(unsigned long)sock,
			local->sin_port,
			local->sin_addr.s_addr);
#endif

	return kernel_bind(sock, (struct sockaddr*)(local), sizeof(struct sockaddr_in));
}

static int spool_connect (struct socket* sock, struct sockaddr_in* remote)
{
	int res;

#ifdef _SPOOL_DEBUG
	printk(KERN_INFO "SPOOL: Connecting socket [%lx] to port [%x] on [%x]\n",
			(unsigned long)sock,
			remote->sin_port,
			remote->sin_addr.s_addr);
#endif

	res = kernel_connect (sock, (struct sockaddr *)remote, sizeof(struct sockaddr_in), SPOOL_SOCK_FLAGS);

	if (res == 0 || res == -EINPROGRESS)
		return (0);

	return res;
}

static int spool_listen(struct spool_instance* si, struct socket* sock, int backlog)
{
	struct sock_list_entry*	sle;
	int res;

#ifdef _SPOOL_DEBUG
	printk(KERN_INFO "SPOOL: Start listening on [%lx]\n", (unsigned long)sock);
#endif

	res = kernel_listen(sock, backlog);
	if (res < 0)
		return res;

	/* Add entry to listener list */

	sle = kmalloc(sizeof(struct sock_list_entry), GFP_KERNEL);

	if(sle == NULL)
	{
		printk(KERN_ERR "SPOOL: Can't allocate memory for listener list entry\n");
		return -ENOMEM;
	}

	sle->sock = sock;
	sle->next = si->lis_socks;
	si->lis_socks = sle;

	return (0);
}

static int spool_accept(struct spool_instance* si, struct spool_sock* sock_list, size_t *size)
{
	struct socket* 			new_sock;
	struct spool_sock 		new_spool_sock;
	size_t					array_size = *size;
	int 					res = 0;
	size_t					i = 0;
	struct sock_list_entry*	sle = si->lis_socks;
	int						accepted = 0;

    while (sle != NULL)
    {
#ifdef _SPOOL_DEBUG
		printk(KERN_INFO "SPOOL: Accept on listening socket [%lx]\n", (long)sle->sock);
#endif

		res = kernel_accept(sle->sock, &new_sock, SPOOL_SOCK_FLAGS);
		if(res >= 0)
		{
			new_spool_sock.sock_h = (long)new_sock;

			add_to_hash(si, new_sock);

			// TODO get peer address here

#ifdef _SPOOL_DEBUG
			printk(KERN_INFO "SPOOL: Accepted socket [%lx]\n", (long)new_spool_sock.sock_h);
#endif
			if (copy_to_user((void __user *)sock_list, &new_spool_sock, sizeof(struct spool_sock)))
			{
				printk(KERN_ERR "SPOOL: Failed to copy spool_sock from Kernel to user space in spool_accept()\n");
				return -EFAULT;
			}

			++sock_list;
			++accepted;

			if(++i == array_size)
				/* Array of accepted sockets is full */
				break;

		}
		else
		{
			if(res != (-EAGAIN))
				printk(KERN_ERR "SPOOL: Accept error %d\n", res);
		}

		sle = sle->next;

		if(sle == NULL)
		{
			if(accepted == 0)
			{
				/* No more connections to accept - finishing */
				break;
			}
			else
			{
				/* If there were accepts we assume that probably there are more
				 * connections to accept - so we will make another round on
				 * listening sockets */
				sle = si->lis_socks;
				accepted = 0;
			}
		}

    }

    if (i < array_size)
    {
    	/* put zero socket handler to the last array element to indicate its end */

		new_spool_sock.sock_h = 0;

		if (copy_to_user((void __user *)sock_list, &new_spool_sock, sizeof(struct spool_sock)))
		{
			printk(KERN_ERR "SPOOL: Failed to copy spool_sock from Kernel to user space in spool_accept()\n");
			return -EFAULT;
		}
    }

	*size = i;

	return (0);
}


static void spool_close(struct spool_instance* si, struct socket* sock)
{
	del_from_hash(si, sock);

#ifdef _SPOOL_DEBUG
	printk(KERN_INFO "SPOOL: Close socket [%lx]\n", (long)sock);
#endif

	if(sock->file == NULL)
		sock_release(sock);
}


/**************************************************************************************/
/*                         Driver interface functions                                 */
/**************************************************************************************/

static long spool_ioctl(struct file *filp, u_int cmd, u_long data)
{
	long 					res = 0;
	struct spool_sock 		k_spool_sock;
	struct spool_instance* 	si;
	struct socket* 			sock;

	si = (struct spool_instance*)filp->private_data;

	switch (cmd)
	{
	case SPOOL_IO_ADDSOCK :

		if (copy_from_user(&k_spool_sock, (void __user *)data, sizeof(struct spool_sock)))
		{
			printk(KERN_ERR "SPOOL: Failed to copy spool_sock to Kernel \n");
			return -EFAULT;
		}

		/* 1) Create socket */

		res = spool_create_sock(si, &sock);
		if (res < 0)
		{
			printk(KERN_ERR "SPOOL: Can't create socket\n");
			break;
		}

		/* 2) Bind socket if local address is specified */
		if (k_spool_sock.local.sin_family == AF_INET)
		{
			res = spool_bind_sock(sock, &k_spool_sock.local);
			if (res < 0)
			{
				spool_close(si, sock);
				printk(KERN_ERR "SPOOL: Can't bind socket\n");
				break;
			}
		}

		/* 3) Start listening or connecting to the server asynchronously */
		if (k_spool_sock.flags & SPOLL_FLAG_LISTENING_SOCK)
		{
			res = spool_listen(si, sock, k_spool_sock.backlog);
			if (res < 0)
			{
				spool_close(si, sock);
				printk(KERN_ERR "SPOOL: Can't listen on socket\n");
				break;
			}

#ifdef _SPOOL_DEBUG
			printk(KERN_INFO "SPOOL: Start listening on socket [%lx]\n", (long)sock);
#endif
		}
		else if(k_spool_sock.flags & SPOOL_FLAG_CLIENT_SOCK)
		{
			res = spool_connect(sock, &k_spool_sock.remote);
			if (res < 0)
			{
				spool_close(si, sock);
				printk(KERN_ERR "SPOOL: Can't connect socket\n");
				break;
			}
		}
		else
		{
			spool_close(si, sock);
			printk(KERN_WARNING "SPOOL: Socket role is not clear from its flags\n");
			break;
		}

		k_spool_sock.sock_h = (long)sock;

		if (copy_to_user((void __user *)data, &k_spool_sock, sizeof(struct spool_sock)))
		{
			spool_close(si, sock);
			printk(KERN_ERR "SARRAY: Failed to copy spool_sock from Kernel to user space\n");
			return -EFAULT;
		}

		break;

	case SPOOL_IO_CLOSESOCK:

		if (copy_from_user(&k_spool_sock, (void __user *)data, sizeof(struct spool_sock)))
		{
			printk(KERN_ERR "SPOOL: Failed to copy spool_sock to Kernel \n");
			return -EFAULT;
		}

#ifdef _SPOOL_DEBUG
		printk(KERN_INFO "SPOOL: Socket release [%lx]\n", k_spool_sock.sock_h);
#endif

		if(k_spool_sock.sock_h != 0)
			spool_close(si, (struct socket*)k_spool_sock.sock_h);

		break;

	case SPOOL_IO_ACCEPT:
		{
			struct spool_accept k_spool_accept;

			if (copy_from_user(&k_spool_accept, (void __user *)data, sizeof(struct spool_accept)))
			{
				printk(KERN_ERR "SPOOL: Failed to copy spool_accept to Kernel \n");
				return -EFAULT;
			}

			res = spool_accept(si, k_spool_accept.sock_list, &k_spool_accept.size);
			if (res < 0)
			{
				printk(KERN_ERR "SPOOL: Accept failed\n");
				break;
			}

			if (copy_to_user((void __user *)data, &k_spool_accept, sizeof(struct spool_accept)))
			{
				printk(KERN_ERR "SPOOL: Failed to copy spool_accept from Kernel to user space\n");
				return -EFAULT;
			}

		}
		break;

	default:
		res = -EOPNOTSUPP;
	}

	return res;
}

static ssize_t spool_read(struct file *filp, char __user *buff,  size_t count, loff_t *offp)
{
	struct spool_sbd* 		u_sbd = (struct spool_sbd*)buff;
	int 					res;
	int 					socks_served = 0;
	struct spool_instance* 	si = (struct spool_instance*)filp->private_data;

	while (u_sbd)
	{
		struct socket*	sock;
		int				mask = 0;

		//printk(KERN_ERR "SPOOL: 111111111111\n");

		if (copy_from_user(&si->k_sbd, (void __user *)u_sbd, sizeof(struct spool_sbd)))
		{
			printk(KERN_ERR "SPOOL: Failed to copy sbd to Kernel from user space at spool_read()\n");
			return -EFAULT;
		}

		if(si->k_sbd.status == SPOOL_STAT_DISABLED || si->k_sbd.sock_h == 0)
			goto next_r;

		//printk(KERN_ERR "SPOOL: 22222222222\n");

		sock = (struct socket*)si->k_sbd.sock_h;
		mask = sock->ops->poll(sock->file, sock, NULL);

		if(!(mask & (POLLIN | POLLRDNORM)))
			goto next_r;

		//printk(KERN_ERR "SPOOL: 3333\n");

		si->iov.iov_base = si->k_sbd.buff + si->k_sbd.offset;
		si->iov.iov_len = si->k_sbd.size - si->k_sbd.offset;

		res = sock_recvmsg(sock, &si->msg, si->iov.iov_len, si->msg.msg_flags);

		//printk(KERN_ERR "SPOOL: 4444444444\n");

		if (res > 0)
		{
			++socks_served;
			si->k_sbd.offset += res;
			si->k_sbd.status = SPOOL_STAT_OK;
		}
		else if(res == 0)
			si->k_sbd.status = SPOOL_STAT_CONN_CLOSED;
		else if (res == -EAGAIN)
		{
			si->k_sbd.status = SPOOL_STAT_NOT_READY;
		}
		else
			si->k_sbd.status = SPOOL_STAT_READ_ERROR;

		//printk(KERN_ERR "SPOOL: 5555\n");

		if (copy_to_user((void __user *)u_sbd, &si->k_sbd, sizeof(struct spool_sbd)))
		{
			printk(KERN_ERR "SPOOL: Failed to copy sbd to user space at spool_read()\n");
			return -EFAULT;
		}

next_r:
		u_sbd = si->k_sbd.next;
	}

	return socks_served;
}

static ssize_t spool_write(struct file *filp, const char __user *buff,  size_t count, loff_t *offp)
{
	struct spool_sbd*		u_sbd = (struct spool_sbd*)buff;
	int 					res;
	int 					socks_served = 0;
	struct spool_instance* 	si  = (struct spool_instance*)filp->private_data;

	while(u_sbd)
	{
		struct socket*	sock;
		int 			mask = 0;

		if (copy_from_user(&si->k_sbd, (void __user *)u_sbd, sizeof(struct spool_sbd)))
		{
			printk(KERN_ERR "SPOOL: Failed to copy sbd to Kernel at spool_write()\n");
			return -EFAULT;
		}

		if(si->k_sbd.status == SPOOL_STAT_DISABLED || si->k_sbd.sock_h == 0)
			goto next_w;

		sock = (struct socket*)si->k_sbd.sock_h;
		mask = sock->ops->poll(sock->file, sock, NULL);

		if(!(mask & (POLLOUT | POLLWRNORM)))
			goto next_w;

		si->iov.iov_base = si->k_sbd.buff + si->k_sbd.offset;
		si->iov.iov_len = si->k_sbd.size - si->k_sbd.offset;

		res = sock_sendmsg(sock, &si->msg, 1);

		if (res > 0)
		{
			++socks_served;
			si->k_sbd.offset += res;
			si->k_sbd.status = SPOOL_STAT_OK;
		}
		else if (res == -EAGAIN)
			si->k_sbd.status = SPOOL_STAT_NOT_READY;
		else
			si->k_sbd.status = SPOOL_STAT_WRITE_ERROR;

		if (copy_to_user((void __user *)u_sbd, &si->k_sbd, sizeof(struct spool_sbd)))
		{
			printk(KERN_ERR "SPOOL: Failed to copy sbd from Kernel to user space at spool_write()\n");
			return -EFAULT;
		}

next_w:
		u_sbd = si->k_sbd.next;
	}

	return socks_served;
}

static int spool_open(struct inode *inode, struct file *filp)
{
	struct spool_instance* si;

	(void)inode;	/* UNUSED */

	si = kmalloc(sizeof(struct spool_instance), GFP_KERNEL);
    if (si == NULL)
    {
        printk(KERN_ERR "SPOOL: Can't allocate memory for Spool instance.\n");
        return -ENOMEM;
    }

	memset(si, 0, sizeof(struct spool_instance));

	si->sock_hash = kmalloc(sizeof(struct spool_list_entry*)*SPOOL_HASH_SIZE, GFP_KERNEL);
    if (si == NULL)
    {
        printk(KERN_ERR "SPOOL: Can't allocate memory for socket hash table.\n");
        return -ENOMEM;
    }

	memset(si->sock_hash, 0, sizeof(struct spool_list_entry*)*SPOOL_HASH_SIZE);

	si->msg.msg_name			= NULL;
	si->msg.msg_iov				= &si->iov;
	si->msg.msg_iovlen			= 1;
	si->msg.msg_control 		= NULL;
	si->msg.msg_controllen 		= 0;
	si->msg.msg_namelen 		= 0;
	si->msg.msg_flags 			= MSG_DONTWAIT;

	filp->private_data = si;

#ifdef _SPOOL_DEBUG
    printk(KERN_INFO "SPOOL: Instance open.\n");
#endif

	return (0);
}

static int spool_release(struct inode *inode, struct file *filp)
{
	(void)inode;	/* UNUSED */

	if (filp->private_data != NULL)
		spool_release_resources (filp->private_data);

#ifdef _SPOOL_DEBUG
    printk(KERN_INFO "SPOOL: Instance released.\n");
#endif

	return (0);
}

static unsigned int spool_poll(struct file *filp, poll_table *wait)
{
    struct spool_instance*	si = filp->private_data;
    struct sock_list_entry*	sle = si->lis_socks;
    unsigned int 			summary_mask = 0;

    while (sle != NULL)
    {
    	unsigned int mask = sle->sock->ops->poll(sle->sock->file, sle->sock, wait);

#ifdef _SPOOL_DEBUG
    	printk(KERN_INFO "SPOOL: Poll on socket [%lx] retured [%d].\n", (long)sle->sock, mask);
#endif
    	summary_mask |= mask;
    	sle = sle->next;
    }

    return summary_mask;
}

struct file_operations spool_fops = {
    .owner 			= THIS_MODULE,
    .read 			=  spool_read,
    .write 			=  spool_write,
    .unlocked_ioctl =  spool_ioctl,
    .open 			=  spool_open,
    .release 		=  spool_release,
    .poll			=  spool_poll
};

static struct miscdevice spool_dev = {

    MISC_DYNAMIC_MINOR,
    "spool",
    &spool_fops
};

static int spool_init(void)
{
     int res;

     res = misc_register(&spool_dev);
     if (res < 0)
     {
         printk(KERN_ERR "SPOOL: Can't register device.\n");
         return res;
     }

     printk(KERN_INFO "SPOOL: Module is loaded.\n");

     return (0);
}

static void spool_exit(void)
{
    misc_deregister(&spool_dev);
    printk(KERN_INFO "SPOOL: Module is unloaded.\n");
}

module_init(spool_init);
module_exit(spool_exit);

