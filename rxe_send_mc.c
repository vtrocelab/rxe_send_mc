/* copy left (c) 2015 Viscore Technologies In. GPL license
 * changed from original mckey.c code to test multicast performance of
 * RoCE send multicast. 
 */

/*
 * Copyright (c) 2005-2007 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * $Id$
 */

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <byteswap.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <rdma/rdma_cma.h>

struct cmatest_node {
	int			id;
	struct rdma_cm_id	*cma_id;
	int			connected;
	struct ibv_pd		*pd;
	struct ibv_cq		*cq;
	struct ibv_mr		*mr;
	struct ibv_ah		*ah;
	uint32_t		remote_qpn;
	uint32_t		remote_qkey;
	void			*mem;
};

struct cmatest {
	struct rdma_event_channel *channel;
	pthread_t 		cmathread;
	struct cmatest_node	*nodes;
	int			conn_index;
	int			connects_left;

	struct sockaddr_in6	dst_in;
	struct sockaddr		*dst_addr;
	struct sockaddr_in6	src_in;
	struct sockaddr		*src_addr;
};

static struct cmatest test;
static int connections = 1;
static int message_size = 100;
static int message_buffer = 1000;
static int message_batch = 10; 
static int is_sender;
static int print_base = -1; 
static int unmapped_addr;
static char *dst_addr;
static char *src_addr;
static enum rdma_port_space port_space = RDMA_PS_UDP;

#define POLL_BATCH 32
#define MAX_PSN 100

static uint32_t global_psn; 
FILE * pFile;

inline int recv_check_psn(struct ibv_wc * wc, int poll_ret, long total_counter)
{
	int i;
	static int loss_counter = 0;
	unsigned long psn_record = 0;
//	static uint32_t loss_psn[MAX_PSN];
	
	if(psn_record == 0) {
		psn_record = wc[0].imm_data;
	}

	for (i=0; i<poll_ret; i++) {
		/* simple consider missed PSN sequnce as lost packet */
		if (wc[i].imm_data != psn_record) {
			loss_counter ++; 
//			loss_psn[loss_counter%MAX_PSN]= wc[i].imm_data;

			printf("PSN %lu is not equal previous %lu\n", (unsigned long) wc[i].imm_data, psn_record); 
			fprintf(pFile, "PSN %lu is not equal previous %lu\n", (unsigned long) wc[i].imm_data, psn_record); 
/*
			if (!(loss_counter % MAX_PSN)) {
				printf("%d package of %lu is missed at PSN = %lu \n",loss_counter,total_counter,psn_record); 
				fprintf(pFile, "%d package of %lu is missed at PSN =%lu\n",loss_counter,total_counter,wc[i].imm_data); 
			}
*/
			psn_record = (unsigned long) wc[i].imm_data;
		}
		psn_record ++;
	}
	return 0; 
}

static int if_continue ()
{
        fd_set readfds;
        int    retval;
        struct timeval tv;
        int    fd_stdin;

        fd_stdin = fileno(stdin);

        FD_ZERO(&readfds);
        FD_SET(fd_stdin, &readfds);

        if(is_sender) {
		tv.tv_sec = 3; tv.tv_usec = 0;
	} else { 
	        tv.tv_sec = 1; tv.tv_usec = 0;
	}

       	printf ("Should we continue? enter any key in 1-3 seconds to break\n");
        retval = select(fd_stdin + 1, &readfds, NULL, NULL, &tv);
        if (retval == -1) {
                fprintf(stderr, "\nError in select : %s\n", strerror(errno));
                exit(1);
        } 

	if (retval == 0) {
                printf("\nContinuing the marathon ... \n");
        } 
	else {
                printf("\nQuite the marathon ... ... \n");
        } 

        return (!retval); //continue if NOT input any key
}

inline void print_line(struct timespec * ts, int done, int batch_size)
{
	struct timespec ts1, ts0;

	ts0 = (* ts); 

	clock_gettime(CLOCK_REALTIME, &ts1);

	double param =  1E9; // One second is 10^9 nano seconds
	long nsec = (ts1.tv_sec - ts0.tv_sec) * param + ts1.tv_nsec - ts0.tv_nsec;
	long bits = (long)batch_size * (long)message_size * 8;
	double bd = (bits/(nsec/param))/1E9; //transfer back to seconds then giga bits

	if(is_sender) {	
		printf ("sending message %d of %d, at bw %lf gbits/s, and %lf msg/msec\n", done, message_buffer * message_batch, bd, batch_size/(nsec/1E6));
	} else {
		printf ("recving message %d of %d, at bw %lf gbits/s, and %lf msg/msec\n", done, message_buffer * message_batch, bd, batch_size/(nsec/1E6));
	}
        
	clock_gettime(CLOCK_REALTIME, ts); //reset the time spec
}

static int create_message(struct cmatest_node *node)
{
	if (!message_size)
		message_buffer = 0;

	if (!message_buffer)
		return 0;

	node->mem = malloc(message_size + sizeof(struct ibv_grh));
	if (!node->mem) {
		printf("failed message allocation\n");
		return -1;
	}
	node->mr = ibv_reg_mr(node->pd, node->mem,
			      message_size + sizeof(struct ibv_grh),
			      IBV_ACCESS_LOCAL_WRITE);
	if (!node->mr) {
		printf("failed to reg MR\n");
		goto err;
	}
	return 0;
err:
	free(node->mem);
	return -1;
}

static int verify_test_params(struct cmatest_node *node)
{
	struct ibv_port_attr port_attr;
	int ret;

	ret = ibv_query_port(node->cma_id->verbs, node->cma_id->port_num,
			     &port_attr);
	if (ret)
		return ret;

	if (message_buffer && message_size > (1 << (port_attr.active_mtu + 7))) {
		printf("rxe_send_mc: message_size %d is larger than active mtu %d\n",
		       message_size, 1 << (port_attr.active_mtu + 7));
		return -EINVAL;
	}

	return 0;
}

static int init_node(struct cmatest_node *node)
{
	struct ibv_qp_init_attr init_qp_attr;
	int cqe, ret;

	node->pd = ibv_alloc_pd(node->cma_id->verbs);
	if (!node->pd) {
		ret = -ENOMEM;
		printf("rxe_send_mc: unable to allocate PD\n");
		goto out;
	}

	cqe = message_buffer ? message_buffer * 2 : 2;
	node->cq = ibv_create_cq(node->cma_id->verbs, cqe, node, 0, 0);
	if (!node->cq) {
		ret = -ENOMEM;
		printf("rxe_send_mc: unable to create CQ\n");
		goto out;
	}

	memset(&init_qp_attr, 0, sizeof init_qp_attr);
	init_qp_attr.cap.max_send_wr = message_buffer ? message_buffer : 1;
	init_qp_attr.cap.max_recv_wr = message_buffer ? message_buffer : 1;
	init_qp_attr.cap.max_send_sge = 1;
	init_qp_attr.cap.max_recv_sge = 1;
	init_qp_attr.qp_context = node;
	init_qp_attr.sq_sig_all = 1; //singal all 
	init_qp_attr.qp_type = IBV_QPT_UD;
	init_qp_attr.send_cq = node->cq;
	init_qp_attr.recv_cq = node->cq;
	ret = rdma_create_qp(node->cma_id, node->pd, &init_qp_attr);
	if (ret) {
		perror("rxe_send_mc: unable to create QP");
		goto out;
	}

	ret = create_message(node);
	if (ret) {
		printf("rxe_send_mc: failed to create messages: %d\n", ret);
		goto out;
	}
out:
	return ret;
}

static int post_recvs(struct cmatest_node *node, int post_depth)
{
	struct ibv_recv_wr recv_wr, *recv_failure;
	struct ibv_sge sge;
	int i, ret = 0;

	if (!message_buffer)
		return 0;

	recv_wr.next = NULL;
	recv_wr.sg_list = &sge;
	recv_wr.num_sge = 1;
	recv_wr.wr_id = (uintptr_t) node;

	sge.length = message_size + sizeof(struct ibv_grh);
	sge.lkey = node->mr->lkey;
	sge.addr = (uintptr_t) node->mem;

	for (i = 0; i < post_depth; i++ ) {
		ret = ibv_post_recv(node->cma_id->qp, &recv_wr, &recv_failure);

		if (ret) {
			printf("failed to post receives: %d\n", ret);
			break;
		}
	}
	return ret;
}

static int post_sends(struct cmatest_node *node, int signal_flag, int post_size)
{
	struct ibv_send_wr send_wr, *bad_send_wr;
	struct ibv_sge sge;
	int i, ret = 0;

	if (!node->connected || !message_buffer)
		return 0;

	send_wr.next = NULL;
	send_wr.sg_list = &sge;
	send_wr.num_sge = 1;
	send_wr.opcode = IBV_WR_SEND_WITH_IMM;
	send_wr.send_flags = signal_flag;
	send_wr.wr_id = (unsigned long)node;
//	send_wr.imm_data = htonl(node->cma_id->qp->qp_num);

	send_wr.wr.ud.ah = node->ah;
	send_wr.wr.ud.remote_qpn = node->remote_qpn;
	send_wr.wr.ud.remote_qkey = node->remote_qkey;

	sge.length = message_size;
	sge.lkey = node->mr->lkey;
	sge.addr = (uintptr_t) node->mem;

	for (i = 0; i < post_size && !ret; i++) {
		send_wr.imm_data = global_psn ++; 
		ret = ibv_post_send(node->cma_id->qp, &send_wr, &bad_send_wr);

		if (ret)
			printf("failed to post sends: %d\n", ret);
	}
	return ret;
}

static void connect_error(void)
{
	test.connects_left--;
}

static int addr_handler(struct cmatest_node *node)
{
	int ret;

	ret = verify_test_params(node);
	if (ret)
		goto err;

	ret = init_node(node);
	if (ret)
		goto err;

	if (!is_sender) {
		ret = post_recvs(node,message_buffer);
		if (ret)
			goto err;
	}

	ret = rdma_join_multicast(node->cma_id, test.dst_addr, node);
	if (ret) {
		perror("rxe_send_mc: failure joining");
		goto err;
	}
	return 0;
err:
	connect_error();
	return ret;
}

static int join_handler(struct cmatest_node *node,
			struct rdma_ud_param *param)
{
	char buf[40];

	inet_ntop(AF_INET6, param->ah_attr.grh.dgid.raw, buf, 40);
	printf("rxe_send_mc: joined dgid: %s mlid 0x%x sl %d\n", buf,
		param->ah_attr.dlid, param->ah_attr.sl);

	node->remote_qpn = param->qp_num;
	node->remote_qkey = param->qkey;
	node->ah = ibv_create_ah(node->pd, &param->ah_attr);
	if (!node->ah) {
		printf("rxe_send_mc: failure creating address handle\n");
		goto err;
	}

	node->connected = 1;
	test.connects_left--;
	return 0;
err:
	connect_error();
	return -1;
}

static int cma_handler(struct rdma_cm_id *cma_id, struct rdma_cm_event *event)
{
	int ret = 0;

	switch (event->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		ret = addr_handler(cma_id->context);
		break;
	case RDMA_CM_EVENT_MULTICAST_JOIN:
		ret = join_handler(cma_id->context, &event->param.ud);
		break;
	case RDMA_CM_EVENT_ADDR_ERROR:
	case RDMA_CM_EVENT_ROUTE_ERROR:
	case RDMA_CM_EVENT_MULTICAST_ERROR:
		printf("rxe_send_mc: event: %s, error: %d\n",
		       rdma_event_str(event->event), event->status);
		connect_error();
		ret = event->status;
		break;
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		/* Cleanup will occur after test completes. */
		break;
	default:
		break;
	}
	return ret;
}

static void *cma_thread(void *arg)
{
	struct rdma_cm_event *event;
	int ret;

	while (1) {
		ret = rdma_get_cm_event(test.channel, &event);
		if (ret) {
			perror("rdma_get_cm_event");
			break;
		}

		switch (event->event) {
		case RDMA_CM_EVENT_MULTICAST_ERROR:
		case RDMA_CM_EVENT_ADDR_CHANGE:
			printf("rxe_send_mc: event: %s, status: %d\n",
			       rdma_event_str(event->event), event->status);
			break;
		default:
			break;
		}

		rdma_ack_cm_event(event);
	}
	return NULL;
}

static void destroy_node(struct cmatest_node *node)
{
	if (!node->cma_id)
		return;

	if (node->ah)
		ibv_destroy_ah(node->ah);

	if (node->cma_id->qp)
		rdma_destroy_qp(node->cma_id);

	if (node->cq)
		ibv_destroy_cq(node->cq);

	if (node->mem) {
		ibv_dereg_mr(node->mr);
		free(node->mem);
	}

	if (node->pd)
		ibv_dealloc_pd(node->pd);

	/* Destroy the RDMA ID after all device resources */
	rdma_destroy_id(node->cma_id);
}

static int alloc_nodes(void)
{
	int ret, i;

	test.nodes = malloc(sizeof *test.nodes * connections);
	if (!test.nodes) {
		printf("rxe_send_mc: unable to allocate memory for test nodes\n");
		return -ENOMEM;
	}
	memset(test.nodes, 0, sizeof *test.nodes * connections);

	for (i = 0; i < connections; i++) {
		test.nodes[i].id = i;
		ret = rdma_create_id(test.channel, &test.nodes[i].cma_id,
				     &test.nodes[i], port_space);
		if (ret)
			goto err;
	}
	return 0;
err:
	while (--i >= 0)
		rdma_destroy_id(test.nodes[i].cma_id);
	free(test.nodes);
	return ret;
}

static void destroy_nodes(void)
{
	int i;

	for (i = 0; i < connections; i++)
		destroy_node(&test.nodes[i]);
	free(test.nodes);
}

static int poll_send_cqs(void)
{
	struct ibv_wc wc[POLL_BATCH];
	int done, i, ret, poll_ret;
	long total_counter = 0;
	
	struct timespec ts0; ts0.tv_sec = -1; ts0.tv_nsec = -1;
	struct timespec tslow, remp; tslow.tv_sec = 0; tslow.tv_nsec = 1; 

	if(!is_sender) {
		printf(" called poll_send_cqs() with receiving side \n");
		return -1;
	}

	if (print_base == -1) print_base = message_buffer * message_batch; 

	for (i = 0; i < connections; i++) {
		if (!test.nodes[i].connected)
			continue;

		do {
		for (done = 0; done < message_buffer * message_batch; done += poll_ret) {
			poll_ret = ibv_poll_cq(test.nodes[i].cq, POLL_BATCH, wc);
			total_counter += poll_ret;

			if (poll_ret < 0) {
				printf("rxe_send_mc: failed polling CQ: %d\n", poll_ret); 
				return poll_ret; 
			} 
			else if (poll_ret > 0) {
				if(ts0.tv_sec == -1 && ts0.tv_nsec == -1){
					clock_gettime(CLOCK_REALTIME, &ts0);
				}
	                        
				if(wc->opcode == IBV_WC_SEND && wc->status == IBV_WC_SUCCESS ) {
/*					if(done % 20 == 0) {
						if(nanosleep(&tslow,&remp)) {
							printf("sleep error\n");
							return -1;
						}
					}
*/
					ret = post_sends(&test.nodes[i],IBV_SEND_SIGNALED,poll_ret);
					if (ret < 0) { 
						printf("rxe_send_mc: failed post sends after polling CQ: %d\n", ret); 
						return ret; 
					}
					if(done != 0 && done % print_base == 0){
						print_line(&ts0, done, print_base);
					}
				}
			} 
		}
		printf ("Have the last message %u of %lu \n", done, total_counter);
//		fprintf (pFile,"Have the last message %u of %lu \n", done, total_counter);
		} while (message_batch >= 1000 && if_continue());
	}
	return 0;
}

static int poll_recv_cqs(void)
{
	struct ibv_wc wc[POLL_BATCH];
	int done, i, ret, poll_ret;
	long total_counter = 0;
	
	struct timespec ts0; ts0.tv_sec = -1; ts0.tv_nsec = -1;

	if(is_sender) {
		printf(" called poll_rec_cqs() with sender side \n");
		return -1;
	}

	if (print_base == -1) print_base = message_buffer * message_batch; 

	for (i = 0; i < connections; i++) {
		if (!test.nodes[i].connected)
			continue;

		do {
		for (done = 0; done < message_buffer * message_batch; done += poll_ret) {
			poll_ret = ibv_poll_cq(test.nodes[i].cq, POLL_BATCH, wc);
			total_counter += poll_ret;

			if (poll_ret < 0) {
				printf("rxe_send_mc: failed polling CQ: %d\n", poll_ret); 
				return poll_ret; 
			} 
			else if (poll_ret > 0) {
				if(ts0.tv_sec == -1 && ts0.tv_nsec == -1){
					clock_gettime(CLOCK_REALTIME, &ts0);
				}
	                        
				ret = recv_check_psn(wc,poll_ret,total_counter);
				if ( ret < 0) {
					return ret;
				}

				ret = post_recvs(&test.nodes[i],poll_ret);
				if (ret < 0) { 
					printf("rxe_send_mc: failed post receives after polling CQ: %d\n", ret); 
					return ret; 
				}

				if (done != 0 && done % print_base == 0) { 
					print_line(&ts0, done, print_base);
				}
			} 
		}
		printf ("Have sent the last message %u of %lu \n", done, total_counter);
		fprintf (pFile,"Have sent the last message %u of %lu \n", done, total_counter);
		} while (message_batch >= 1000 && if_continue());
	}
	return 0;
}

static int connect_events(void)
{
	struct rdma_cm_event *event;
	int ret = 0;

	while (test.connects_left && !ret) {
		ret = rdma_get_cm_event(test.channel, &event);
		if (!ret) {
			ret = cma_handler(event->id, event);
			rdma_ack_cm_event(event);
		}
	}
	return ret;
}

static int get_addr(char *dst, struct sockaddr *addr)
{
	struct addrinfo *res;
	int ret;

	ret = getaddrinfo(dst, NULL, NULL, &res);
	if (ret) {
		printf("getaddrinfo failed - invalid hostname or IP address\n");
		return ret;
	}

	memcpy(addr, res->ai_addr, res->ai_addrlen);

	freeaddrinfo(res);
	return ret;
}

static int run(void)
{
	int i, ret;
	
	printf("rxe_send_mc: starting %s\n", is_sender ? "client" : "server");
	if (src_addr) {
		ret = get_addr(src_addr, (struct sockaddr *) &test.src_in);
		if (ret)
			return ret;
	}

	ret = get_addr(dst_addr, (struct sockaddr *) &test.dst_in);
	if (ret)
		return ret;

	printf("rxe_send_mc: joining\n");
	for (i = 0; i < connections; i++) {
		if (src_addr) {
			ret = rdma_bind_addr(test.nodes[i].cma_id,
					     test.src_addr);
			if (ret) {
				perror("rxe_send_mc: addr bind failure");
				connect_error();
				return ret;
			}
		}

		if (unmapped_addr)
			ret = addr_handler(&test.nodes[i]);
		else
			ret = rdma_resolve_addr(test.nodes[i].cma_id,
						test.src_addr, test.dst_addr,
						2000);
		if (ret) {
			perror("rxe_send_mc: resolve addr failure");
			connect_error();
			return ret;
		}
	}

	ret = connect_events();
	if (ret)
		goto out;

	pthread_create(&test.cmathread, NULL, cma_thread, NULL);

	/*
	 * Pause to give SM chance to configure switches.  We don't want to
	 * handle reliability issue in this simple test program.
	 */
	sleep(3);

	if (message_batch) {
		if (is_sender) {
			printf("initiating data transfers\n");
			for (i = 0; i < connections; i++) {
				ret = post_sends(&test.nodes[i], IBV_SEND_SIGNALED, 50);
				if (ret)
					goto out;
			}
			ret = poll_send_cqs();
		} else {
			printf("receiving data transfers\n");
			ret = poll_recv_cqs();
		}


		if (ret) 
			goto out;

		printf("data transfers complete\n");
	}
out:
	for (i = 0; i < connections; i++) {
		ret = rdma_leave_multicast(test.nodes[i].cma_id,
					   test.dst_addr);
		if (ret)
			perror("rxe_send_mc: failure leaving");
	}
	return ret;
}

int main(int argc, char **argv)
{
	int op, ret;

	struct timespec ts1;
	clock_gettime(CLOCK_REALTIME, &ts1);
	srand(ts1.tv_nsec);
	global_psn = rand(); 

	pFile = fopen ("losspacket","w");

	while ((op = getopt(argc, argv, "m:M:sb:c:C:i:S:p:")) != -1) {
		switch (op) {
		case 'm':
			dst_addr = optarg;
			break;
		case 'M':
			unmapped_addr = 1;
			dst_addr = optarg;
			break;
		case 's':
			is_sender = 1;
			break;
		case 'b':
			src_addr = optarg;
			test.src_addr = (struct sockaddr *) &test.src_in;
			break;
		case 'c':
			connections = atoi(optarg);
			break;
		case 'C':
			message_batch *= atoi(optarg);
			break;
		case 'i':
			print_base = 10000 * atoi(optarg); 
			break;
		case 'S':
			message_size = atoi(optarg);
			break;
		case 'p':
			port_space = strtol(optarg, NULL, 0);
			break;
		default:
			printf("usage: %s\n", argv[0]);
			printf("\t-m multicast_address\n");
			printf("\t[-M unmapped_multicast_address]\n"
			       "\t replaces -m and requires -b\n");
			printf("\t[-s(ender)]\n");
			printf("\t[-b bind_address]\n");
			printf("\t[-c connections]\n");
			printf("\t[-C message_buffer]\n");
			printf("\t[-S message_size]\n");
			printf("\t[-p port_space - %#x for UDP (default), "
			       "%#x for IPOIB]\n", RDMA_PS_UDP, RDMA_PS_IPOIB);
			exit(1);
		}
	}

	if (unmapped_addr && !src_addr) {
		printf("unmapped multicast address requires binding "
			"to source address\n");
		exit(1);
	}

	test.dst_addr = (struct sockaddr *) &test.dst_in;
	test.connects_left = connections;

	test.channel = rdma_create_event_channel();
	if (!test.channel) {
		perror("failed to create event channel");
		exit(1);
	}

	if (alloc_nodes())
		exit(1);

	ret = run();

	fclose (pFile); 
	printf("test complete\n");
	destroy_nodes();
	rdma_destroy_event_channel(test.channel);

	printf("return status %d\n", ret);
	return ret;
}
