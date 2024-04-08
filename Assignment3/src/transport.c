/*
 * transport.c
 *
 * EN.601.414/614: HW#3 (STCP)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file.
 *
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define TH_LOCAL_WIN 3072
#define TH_OFF 5;

enum
{
    CSTATE_ESTABLISHED

}; /* obviously you should have more states */

/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done; /* TRUE once connection is closed */

    int connection_state; /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;

    /* any other connection-wide global variables go here */

    // last byte received
    tcp_seq last_recv_sequence_num;

    // last byte sent
    tcp_seq last_send_sequence_num;

    // last byte acknoledged
    tcp_seq next_expected_sequence_num;

    int sent_FIN;
} context_t;

void our_dprintf(const char *format, ...);
static void generate_initial_seq_num(context_t *ctx, int seed);
static void control_loop(mysocket_t sd, context_t *ctx);
static ssize_t send_data_packet(mysocket_t sd, context_t *ctx, uint8_t flags, int is_ack, char *data_bytes, ssize_t data_len);
static ssize_t receive_data_packet(mysocket_t sd, context_t *ctx, char *buffer, int is_ack);
static int check_packet_flags(STCPHeader *packet_hdr, uint8_t expected_flags);
static void print_all_sequence_number(context_t *ctx);

/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
    context_t *ctx;

    ctx = (context_t *)calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx, is_active ? 42 : 25);

    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */

    if (is_active)
    {
        // send syn packet
        ctx->last_send_sequence_num = ctx->initial_sequence_num;
        send_data_packet(sd, ctx, TH_SYN, 0, NULL, 0);

        // wait for syn ack
        unsigned int wait_code = stcp_wait_for_event(sd, NETWORK_DATA, NULL);
        char *recv_syn_ack_packet = (char *)malloc(sizeof(STCPHeader) + STCP_MSS);
        receive_data_packet(sd, ctx, recv_syn_ack_packet, 1);
        check_packet_flags((STCPHeader *)recv_syn_ack_packet, (TH_ACK | TH_SYN));
        free(recv_syn_ack_packet);

        // send ack
        send_data_packet(sd, ctx, TH_ACK, 1, NULL, 0);
    }
    else
    {
        // wait for syn
        unsigned int wait_code = stcp_wait_for_event(sd, NETWORK_DATA, NULL);
        char *recv_syn_packet = (char *)malloc(sizeof(STCPHeader) + STCP_MSS);
        receive_data_packet(sd, ctx, recv_syn_packet, 0);
        check_packet_flags((STCPHeader *)recv_syn_packet, TH_SYN);
        free(recv_syn_packet);

        // send syn ack
        ctx->last_send_sequence_num = ctx->initial_sequence_num;
        send_data_packet(sd, ctx, (TH_ACK | TH_SYN), 1, NULL, 0);

        // wait for ack
        wait_code = stcp_wait_for_event(sd, NETWORK_DATA, NULL);
        char *recv_ack_packet = (char *)malloc(sizeof(STCPHeader) + STCP_MSS);
        receive_data_packet(sd, ctx, recv_ack_packet, 1);
        check_packet_flags((STCPHeader *)recv_ack_packet, TH_ACK);
        free(recv_ack_packet);
    }
    ctx->connection_state = CSTATE_ESTABLISHED;
    stcp_unblock_application(sd);

    control_loop(sd, ctx);

    /* do any cleanup here */
    free(ctx);
}

/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx, int seed)
{
    assert(ctx);

#ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->initial_sequence_num = 1;
#else
    /* you have to fill this up */
    srand(seed);
    ctx->initial_sequence_num = rand() % 256;
#endif
}

/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx)
{
    assert(ctx);

    // set sent_FIN to false
    ctx->sent_FIN = 0;

    while (!ctx->done)
    {
        unsigned int event;

        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, ANY_EVENT, NULL);

        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA)
        {
            /* the application has requested that data be sent */
            /* see stcp_app_recv() */
            // receive packet
            size_t avail_window = TH_LOCAL_WIN - (ctx->last_send_sequence_num - ctx->next_expected_sequence_num);
            size_t max_data_fill = (avail_window < STCP_MSS) ? avail_window : STCP_MSS;
            our_dprintf("largest available window size: %ld\n ", avail_window);
            our_dprintf("max data fill: %ld\n ", max_data_fill);

            char *data_buffer = (char *)malloc(STCP_MSS);
            ssize_t recv_code = stcp_app_recv(sd, data_buffer, max_data_fill);
            if (recv_code == -1)
                our_dprintf("failed receiving data packet\n");
            else
                our_dprintf("received data packet with length %ld\n", recv_code);

            send_data_packet(sd, ctx, 0, 0, data_buffer, recv_code);
            free(data_buffer);
        }

        if (event & NETWORK_DATA)
        {
            /* received data from STCP peer */
            // receive packet
            char *recv_network_packet = (char *)malloc(sizeof(STCPHeader) + STCP_MSS);
            ssize_t recv_code = receive_data_packet(sd, ctx, recv_network_packet, 0);
            STCPHeader *recv_network_packet_hdr = (STCPHeader *)recv_network_packet;
            // check the flag bit
            if (recv_network_packet_hdr->th_flags == TH_ACK)
            {
                // if ACK, modify the next sequence number epected
                our_dprintf("received network data packet with ACK flag\n");
                ctx->next_expected_sequence_num = recv_network_packet_hdr->th_ack;
                ctx->done = ctx->sent_FIN ? 1 : 0;
            }
            else if (recv_network_packet_hdr->th_flags == TH_FIN)
            {
                our_dprintf("received network data packet with FIN flag\n");
                // send FIN-ACK
                send_data_packet(sd, ctx, (TH_ACK | TH_FIN), 1, NULL, 0);
                ctx->done = 1;
                ctx->sent_FIN = 1;
                stcp_fin_received(sd);
            }
            else if (recv_network_packet_hdr->th_flags == (TH_FIN | TH_ACK))
            {
                our_dprintf("received network data packet with FIN ACK flag\n");
                // send ACK
                send_data_packet(sd, ctx, TH_ACK, 1, NULL, 0);
                ctx->done = 1;
                stcp_fin_received(sd);
            }
            else
            {
                // if other, send ACK
                unsigned int data_byte = recv_code - sizeof(STCPHeader);
                our_dprintf("received network data packet with data size %d\n", data_byte);
                if (data_byte > 0)
                {
                    send_data_packet(sd, ctx, TH_ACK, 1, NULL, 0);
                    stcp_app_send(sd, recv_network_packet + sizeof(STCPHeader), data_byte);
                }
            }
            free(recv_network_packet);
        }
        if (event & APP_CLOSE_REQUESTED)
        {
            // 1. send FIN
            send_data_packet(sd, ctx, TH_FIN, 0, NULL, 0);
            ctx->sent_FIN = 1;
        }

        /* etc. */
    }
}

/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 *
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format, ...)
{
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}

static ssize_t send_data_packet(mysocket_t sd, context_t *ctx, uint8_t flags, int is_ack, char *data_bytes, ssize_t data_len)
{
    int return_val = 0;
    char *packet = (char *)malloc(sizeof(STCPHeader) + data_len);
    STCPHeader *packet_hdr = (STCPHeader *)packet;
    packet_hdr->th_seq = ctx->last_send_sequence_num;
    packet_hdr->th_off = TH_OFF;
    packet_hdr->th_flags = flags;
    packet_hdr->th_win = TH_LOCAL_WIN;
    if (is_ack)
        packet_hdr->th_ack = ctx->last_recv_sequence_num + 1;
    if (data_bytes)
        memcpy(packet + sizeof(STCPHeader), data_bytes, data_len);
    ssize_t send_code = stcp_network_send(sd, (const void *)packet, sizeof(STCPHeader) + data_len, NULL);
    if (send_code == -1)
        our_dprintf("failed sending packet\n");
    else if ((long unsigned int)send_code == sizeof(STCPHeader) + data_len)
        our_dprintf("succeeded sending packet\n");
    else
        our_dprintf("succeeded sending packet but incomplete send, expected %ld sent, but only sent %ld\n", sizeof(STCPHeader) + data_len, send_code);
    free(packet);
    ctx->last_send_sequence_num += (data_len > 0) ? data_len : 1;
    print_all_sequence_number(ctx);
    return send_code;
}

static ssize_t receive_data_packet(mysocket_t sd, context_t *ctx, char *buffer, int is_ack)
{
    ssize_t recv_code = stcp_network_recv(sd, buffer, TH_LOCAL_WIN);
    STCPHeader *packet_hdr = (STCPHeader *)buffer;
    if (recv_code == -1)
    {
        our_dprintf("failed receiving packet\n");
    }
    else
    {
        our_dprintf("received packet with length %ld\n", recv_code);
    }
    ctx->last_recv_sequence_num = packet_hdr->th_seq;
    if (is_ack)
        ctx->next_expected_sequence_num = packet_hdr->th_ack;
    print_all_sequence_number(ctx);
    return recv_code;
}

static const char *find_flag_name(uint8_t flags)
{
    switch (flags)
    {
    case TH_ACK:
        return "ACK packet";
    case TH_SYN:
        return "SYN packet";
    case TH_FIN:
        return "FIN packet";
    case (TH_ACK | TH_SYN):
        return "ACK-SYN packet";
    case (TH_ACK | TH_FIN):
        return "ACK-FIN packet";
    default:
        break;
    }
    return "unidentified packet";
}

static int check_packet_flags(STCPHeader *packet_hdr, uint8_t expected_flags)
{
    uint8_t packet_flags = packet_hdr->th_flags;
    const char *expected_flags_name = find_flag_name(expected_flags);
    const char *packet_flags_name = find_flag_name(packet_flags);
    if (packet_flags == expected_flags)
    {
        our_dprintf("Correct packet flags: expected packet flag %s. \n\n", expected_flags_name);
        return 1;
    }
    our_dprintf("Incorrect packet flags: expected packet flag %s, got %s. \n\n", expected_flags_name, packet_flags_name);
    return 0;
}

static void print_all_sequence_number(context_t *ctx)
{
    our_dprintf("last sequence number sent: %u\n", ctx->last_send_sequence_num);
    our_dprintf("next sequence number expected: %u\n", ctx->next_expected_sequence_num);
    our_dprintf("last sequence number received: %u\n\n", ctx->last_recv_sequence_num);
}
