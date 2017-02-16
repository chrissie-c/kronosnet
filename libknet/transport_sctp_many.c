#include "config.h"

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>

#include "compat.h"
#include "host.h"
#include "link.h"
#include "logging.h"
#include "common.h"
#include "transports.h"
#include "threads_common.h"

#ifdef HAVE_NETINET_SCTP_H
#include <netinet/sctp.h>

/*
 * https://en.wikipedia.org/wiki/SCTP_packet_structure
 */
#define KNET_PMTUD_SCTP_OVERHEAD_COMMON 12
#define KNET_PMTUD_SCTP_OVERHEAD_DATA_CHUNK 16
#define KNET_PMTUD_SCTP_OVERHEAD KNET_PMTUD_SCTP_OVERHEAD_COMMON + KNET_PMTUD_SCTP_OVERHEAD_DATA_CHUNK

typedef struct sctp_many_handle_info {
	struct knet_list_head links_list;
} sctp_many_handle_info_t;

typedef struct sctp_many_link_info {
	struct knet_list_head list;
	struct sockaddr_storage local_address;
	int socket_fd;
	int on_epoll;
	char mread_buf[KNET_DATABUFSIZE];
	ssize_t mread_len;
} sctp_many_link_info_t;

static int _enable_sctp_notifications(knet_handle_t knet_h, int sock, const char *type)
{
	int err = 0, savederrno = 0;
	struct sctp_event_subscribe events;

	memset(&events, 0, sizeof (events));
	events.sctp_data_io_event = 1;
	events.sctp_association_event = 1;
	events.sctp_send_failure_event = 1;
	events.sctp_address_event = 1;
	events.sctp_peer_error_event = 1;
	events.sctp_shutdown_event = 1;
	if (setsockopt(sock, IPPROTO_SCTP, SCTP_EVENTS, &events, sizeof (events)) < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to enable %s events: %s",
			type, strerror(savederrno));
	}

	errno = savederrno;
	return err;
}

static int _configure_sctp_socket(knet_handle_t knet_h, int sock, struct sockaddr_storage *address, const char *type)
{
	int err = 0, savederrno = 0;
	int value;
	int level;

#ifdef SOL_SCTP
	level = SOL_SCTP;
#else
	level = IPPROTO_SCTP;
#endif

	if (_configure_transport_socket(knet_h, sock, address, type) < 0) {
		savederrno = errno;
		err = -1;
		goto exit_error;
	}

	value = 1;
	if (setsockopt(sock, level, SCTP_NODELAY, &value, sizeof(value)) < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSPORT, "Unable to set sctp nodelay: %s",
			strerror(savederrno));
		goto exit_error;
	}

	if (_enable_sctp_notifications(knet_h, sock, type) < 0) {
		savederrno = errno;
		err = -1;
	}

exit_error:
	errno = savederrno;
	return err;
}

static int sctp_many_transport_tx_sock_error(knet_handle_t knet_h, int sockfd, int recv_err, int recv_errno)
{
	if (recv_err < 0) {
		if (recv_errno == EAGAIN) {
#ifdef DEBUG
			log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Sock: %d is overloaded. Slowing TX down", sockfd);
#endif
			usleep(KNET_THREADS_TIMERES / 16);
			return 1;
		}
		return -1;
	}
	return 0;
}

/*
 * no error management yet
 */
static int sctp_many_transport_rx_sock_error(knet_handle_t knet_h, int sockfd, int recv_err, int recv_errno)
{
	return 0;
}

/*
 * NOTE: sctp_transport_rx_is_data is called with global rdlock
 *       delegate any FD error management to sctp_transport_rx_sock_error
 *       and keep this code to parsing incoming data only
 */
static int sctp_many_transport_rx_is_data(knet_handle_t knet_h, int sockfd, struct knet_mmsghdr *msg)
{
	int i;
	struct iovec *iov = msg->msg_hdr.msg_iov;
	size_t iovlen = msg->msg_hdr.msg_iovlen;
	struct sctp_assoc_change *sac;
	union sctp_notification  *snp;
	sctp_many_link_info_t *info = knet_h->knet_transport_fd_tracker[sockfd].data;

	if (!(msg->msg_hdr.msg_flags & MSG_NOTIFICATION)) {
		if (msg->msg_len == 0) {
			log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "received 0 bytes len packet: %d", sockfd);
			/*
			 * NOTE: with event notification enabled, we receive error twice:
			 *       1) from the event notification
			 *       2) followed by a 0 byte msg_len
			 *
			 * This is generally not a problem if not for causing extra
			 * handling for the same issue. Should we drop notifications
			 * and keep the code generic (handle all errors via msg_len = 0)
			 * or keep the duplication as safety measure, or drop msg_len = 0
			 * handling (what about sockets without events enabled?)
			 */
			sctp_many_transport_rx_sock_error(knet_h, sockfd, 1, 0);
			return 1;
		}
		/*
		 * missing MSG_EOR has to be treated as a short read
		 * from the socket and we need to fill in the mread buf
		 * while we wait for MSG_EOR
		 */
		if (!(msg->msg_hdr.msg_flags & MSG_EOR)) {
			/*
			 * copy the incoming data into mread_buf + mread_len (incremental)
			 * and increase mread_len
			 */
			memmove(info->mread_buf + info->mread_len, iov->iov_base, msg->msg_len);
			info->mread_len = info->mread_len + msg->msg_len;
			return 0;
		}
		/*
		 * got EOR.
		 * if mread_len is > 0 we are completing a packet from short reads
		 * complete reassembling the packet in mread_buf, copy it back in the iov
		 * and set the iov/msg len numbers (size) correctly
		 */
		if (info->mread_len) {
			/*
			 * add last fragment to mread_buf
			 */
			memmove(info->mread_buf + info->mread_len, iov->iov_base, msg->msg_len);
			info->mread_len = info->mread_len + msg->msg_len;
			/*
			 * move all back into the iovec
			 */
			memmove(iov->iov_base, info->mread_buf, info->mread_len);
			msg->msg_len = info->mread_len;
			info->mread_len = 0;
		}
		return 2;
	}

	if (!(msg->msg_hdr.msg_flags & MSG_EOR)) {
		return 1;
	}

	for (i=0; i< iovlen; i++) {
		snp = iov[i].iov_base;

		switch (snp->sn_header.sn_type) {
			case SCTP_ASSOC_CHANGE:
				log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "[event] sctp assoc change");
				sac = &snp->sn_assoc_change;
				if (sac->sac_state == SCTP_COMM_LOST) {
					log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "[event] sctp assoc change: comm_lost");
					sctp_many_transport_rx_sock_error(knet_h, sockfd, 2, 0);
				}
				break;
			case SCTP_SHUTDOWN_EVENT:
				log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "[event] sctp shutdown event");
				sctp_many_transport_rx_sock_error(knet_h, sockfd, 2, 0);
				break;
			case SCTP_SEND_FAILED:
				log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "[event] sctp send failed");
				break;
			case SCTP_PEER_ADDR_CHANGE:
				log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "[event] sctp peer addr change");
				break;
			case SCTP_REMOTE_ERROR:
				log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "[event] sctp remote error");
				break;
			default:
				log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "[event] unknown sctp event type: %hu\n", snp->sn_header.sn_type);
				break;
		}
	}
	return 0;
}

/*
 * Links config/clear. Both called with global wrlock from link_set_config/clear_config
 */
static int sctp_many_transport_link_set_config(knet_handle_t knet_h, struct knet_link *kn_link)
{
	int savederrno = 0, err = 0;
	int sock = -1;
	sctp_many_link_info_t *info;
	sctp_many_handle_info_t *handle_info = knet_h->transports[KNET_TRANSPORT_SCTP_MANY];
	struct epoll_event ev;

	/*
	 * Only allocate a new link if the local address is different
	 */

	knet_list_for_each_entry(info, &handle_info->links_list, list) {
		if (memcmp(&info->local_address, &kn_link->src_addr, sizeof(struct sockaddr_storage)) == 0) {
			log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "Re-using existing SCTP socket for new link");
			kn_link->outsock = info->socket_fd;
			kn_link->transport_link = info;
			kn_link->transport_connected = 1;
			return 0;
		}
	}

	info = malloc(sizeof(sctp_many_link_info_t));
	if (!info) {
		err = -1;
		goto exit_error;
	}

	memset(info, 0, sizeof(sctp_many_link_info_t));

	sock = socket(kn_link->src_addr.ss_family, SOCK_SEQPACKET, IPPROTO_SCTP);
	if (sock < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_LISTENER, "Unable to create listener socket: %s",
			strerror(savederrno));
		goto exit_error;
	}

	if (_configure_sctp_socket(knet_h, sock, &kn_link->src_addr, "SCTP listener") < 0) {
		savederrno = errno;
		err = -1;
		goto exit_error;
	}

	if (bind(sock, (struct sockaddr *)&kn_link->src_addr, sockaddr_len(&kn_link->src_addr))) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to bind listener socket: %s",
			strerror(savederrno));
		goto exit_error;
	}

	if (listen(sock, 5) < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to listen on listener socket: %s",
			strerror(savederrno));
		goto exit_error;
	}

	memset(&ev, 0, sizeof(struct epoll_event));
	ev.events = EPOLLIN;
	ev.data.fd = sock;

	if (epoll_ctl(knet_h->recv_from_links_epollfd, EPOLL_CTL_ADD, sock, &ev)) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to add listener to epoll pool: %s",
			strerror(savederrno));
		goto exit_error;
	}

	info->on_epoll = 1;

	if (_set_fd_tracker(knet_h, sock, KNET_TRANSPORT_SCTP_MANY, 0, info) < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to set fd tracker: %s",
			strerror(savederrno));
		goto exit_error;
	}

	memcpy(&info->local_address, &kn_link->src_addr, sizeof(struct sockaddr_storage));
	info->socket_fd = sock;
	knet_list_add(&info->list, &handle_info->links_list);

	kn_link->outsock = sock;
	kn_link->transport_link = info;
	kn_link->transport_connected = 1;

exit_error:
	if (err) {
		if (info) {
			if (info->socket_fd) {
				close(info->socket_fd);
			}
			kn_link->transport_link = NULL;
			free(info);
		}
	}
	errno = savederrno;
	return err;
}

/*
 * called with global wrlock
 */
static int sctp_many_transport_link_clear_config(knet_handle_t knet_h, struct knet_link *link)
{
	int err = 0, savederrno = 0;
	int found = 0;
	struct knet_host *host;
	int link_idx;
	sctp_many_link_info_t *info = link->transport_link;
	struct epoll_event ev;

	for (host = knet_h->host_head; host != NULL; host = host->next) {
		for (link_idx = 0; link_idx < KNET_MAX_LINK; link_idx++) {
			if (&host->link[link_idx] == link)
				continue;

			if ((host->link[link_idx].transport_link == info) &&
			    (host->link[link_idx].status.enabled == 1)) {
				found = 1;
				break;
			}
		}
	}

	if (found) {
		log_debug(knet_h, KNET_SUB_TRANSP_SCTP, "SCTP socket %d still in use", info->socket_fd);
		savederrno = EBUSY;
		err = -1;
		goto exit_error;
	}

	if (info->on_epoll) {
		memset(&ev, 0, sizeof(struct epoll_event));
		ev.events = EPOLLIN;
		ev.data.fd = info->socket_fd;

		if (epoll_ctl(knet_h->recv_from_links_epollfd, EPOLL_CTL_DEL, info->socket_fd, &ev) < 0) {
			savederrno = errno;
			err = -1;
			log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to remove SCTP socket from epoll poll: %s",
				strerror(errno));
			goto exit_error;
		}
		info->on_epoll = 0;
	}

	if (_set_fd_tracker(knet_h, info->socket_fd, KNET_MAX_TRANSPORTS, 0, NULL) < 0) {
		savederrno = errno;
		err = -1;
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Unable to set fd tracker: %s",
			strerror(savederrno));
		goto exit_error;
	}

	close(info->socket_fd);
	knet_list_del(&info->list);
	free(link->transport_link);

exit_error:
	errno = savederrno;
	return err;
}

/*
 * transport_free and transport_init are
 * called only from knet_handle_new and knet_handle_free.
 * all resources (hosts/links) should have been already freed at this point
 * and they are called in a write locked context, hence they
 * don't need their own locking.
 */

static int sctp_many_transport_free(knet_handle_t knet_h)
{
	sctp_many_handle_info_t *handle_info;

	if (!knet_h->transports[KNET_TRANSPORT_SCTP_MANY]) {
		errno = EINVAL;
		return -1;
	}

	handle_info = knet_h->transports[KNET_TRANSPORT_SCTP_MANY];

	/*
	 * keep it here while we debug list usage and such
	 */
	if (!knet_list_empty(&handle_info->links_list)) {
		log_err(knet_h, KNET_SUB_TRANSP_SCTP, "Internal error. handle list is not empty");
		return -1;
	}

	free(handle_info);

	knet_h->transports[KNET_TRANSPORT_SCTP_MANY] = NULL;

	return 0;
}

static int sctp_many_transport_init(knet_handle_t knet_h)
{
	sctp_many_handle_info_t *handle_info;

	if (knet_h->transports[KNET_TRANSPORT_SCTP_MANY]) {
		errno = EEXIST;
		return -1;
	}

	handle_info = malloc(sizeof(sctp_many_handle_info_t));
	if (!handle_info) {
		return -1;
	}

	memset(handle_info, 0,sizeof(sctp_many_handle_info_t));

	knet_h->transports[KNET_TRANSPORT_SCTP_MANY] = handle_info;

	knet_list_init(&handle_info->links_list);

	return 0;
}

static int sctp_many_transport_link_dyn_connect(knet_handle_t knet_h, int sockfd, struct knet_link *kn_link)
{
	kn_link->status.dynconnected = 1;
	return 0;
}

static knet_transport_ops_t sctp_many_transport_ops = {
	.transport_name = "SCTP_MANY",
	.transport_id = KNET_TRANSPORT_SCTP_MANY,
	.transport_mtu_overhead = KNET_PMTUD_SCTP_OVERHEAD,
	.transport_init = sctp_many_transport_init,
	.transport_free = sctp_many_transport_free,
	.transport_link_set_config = sctp_many_transport_link_set_config,
	.transport_link_clear_config = sctp_many_transport_link_clear_config,
	.transport_link_dyn_connect = sctp_many_transport_link_dyn_connect,
	.transport_rx_sock_error = sctp_many_transport_rx_sock_error,
	.transport_tx_sock_error = sctp_many_transport_tx_sock_error,
	.transport_rx_is_data = sctp_many_transport_rx_is_data,
};

knet_transport_ops_t *get_sctp_many_transport()
{

	return &sctp_many_transport_ops;
}
#else // HAVE_NETINET_SCTP_H
knet_transport_ops_t *get_sctp_many_transport()
{
	return NULL;
}
#endif
