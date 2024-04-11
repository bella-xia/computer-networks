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
#include <arpa/inet.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define TH_LOCAL_WIN 3072
#define TH_OFF 5;

enum network_state
{
    CLIENT_UNCONNECTED = 42, /*client initialized. Unconnected*/

    SERVER_SYN_WAIT, /*server initialized. waiting for client SYN*/

    CLIENT_SYN_ACK_WAIT, /*client sent SYN packet. Wating for SYN-ACK*/

    SERVER_ACK_WAIT, /*Server sent SYN-ACK. Waiting for ACK*/

    CSTATE_ESTABLISHED, /*common connected*/

    CLIENT_FIN_ACK_WAIT, /*the first ending side waiting for FIN-ACK*/

    CLIENT_FIN_WAIT_2, /* the first ending side waitign for FIn from the other side*/

    SERVER_SEND, /*when one side ends connection*/

    SERVER_FIN_ACK_WAIT /*the second ending side waiting for FIN-ACK*/

}; /* obviously you should have more states */

/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done; /* TRUE once connection is closed */

    enum network_state connection_state; /* state of the connection (established, etc.) */

    tcp_seq initial_sequence_num;

    /* any other connection-wide global variables go here */

    // last byte received
    tcp_seq last_recv_sequence_num;

    // last byte sent
    tcp_seq last_send_sequence_num;

    // last byte acknoledged
    tcp_seq next_expected_sequence_num;

    // the other end host's congestion window size
    size_t transmit_window_size;

} context_t;

/// @brief customizable printf function
/// @param format the formatted char array to be printed
/// @param ... any other necessary params
void our_dprintf(const char *format, ...);

/// @brief generate randomized initial sequence number
/// @param ctx context info
/// @param seed seed for random number generation
static void generate_initial_seq_num(context_t *ctx, int seed);

/// @brief handling three-way handshake of client
/// @param sd socket number
/// @param ctx context info
static void handle_client_init(mysocket_t sd, context_t *ctx);

/// @brief handling three-way handshake of server
/// @param sd socket number
/// @param ctx context info
static void handle_server_init(mysocket_t sd, context_t *ctx);

/// @brief handling incoming network data
/// @param sd socket number
/// @param ctx context info
static void handle_network_data(mysocket_t sd, context_t *ctx);

/// @brief handling incoming application data
/// @param sd socket number
/// @param ctx context info
static void handle_app_data(mysocket_t sd, context_t *ctx);

/// @brief handling indication of application closing
/// @param sd socket number
/// @param ctx context info
static void handle_app_closing(mysocket_t sd, context_t *ctx);

/// @brief control loop for incoming TCP packets
/// @param sd socket number
/// @param ctx context info
static void control_loop(mysocket_t sd, context_t *ctx);

/// @brief helper function for sending any STCP packet
/// @param sd socket number
/// @param ctx context info
/// @param flags STCP flags
/// @param is_ack boolean value on whether it has ACK bit
/// @param data_bytes data stream (if it has data body)
/// @param data_len length of the data stream
/// @return the size of the data packet sent
static ssize_t send_data_packet(mysocket_t sd, context_t *ctx, uint8_t flags, bool_t is_ack,
                                char *data_bytes, ssize_t data_len);

/// @brief helper function for receiving any STCP packet
/// @param sd socket number
/// @param ctx context info
/// @param buffer allocated buffer for received packet write
/// @param is_ack   boolean value on whether it is expected to be an ACK packet
/// @return the size of the data packet received
static ssize_t receive_data_packet(mysocket_t sd, context_t *ctx, char *buffer, bool_t is_ack);

/// @brief check whether the packet flags are as expected
/// @param packet_hdr the header struct for the STCP packet
/// @param expected_flags expected flags bit
/// @return
static int check_packet_flags(STCPHeader *packet_hdr, uint8_t expected_flags);

/// @brief helper function for printing out the sequence number and congestion window information
/// @param ctx context info
static void print_all_sequence_number_and_window(context_t *ctx);

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
        handle_client_init(sd, ctx);

    else
        handle_server_init(sd, ctx);

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

    // looping over control loop under connection is closed
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
            handle_app_data(sd, ctx);
        }

        if (event & NETWORK_DATA)
        {
            /* received data from STCP peer */
            // receive packet
            handle_network_data(sd, ctx);
        }
        if (event & APP_CLOSE_REQUESTED)
        {
            handle_app_closing(sd, ctx);
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

static void handle_client_init(mysocket_t sd, context_t *ctx)
{
    // initialize connection state of client
    ctx->connection_state = CLIENT_UNCONNECTED;
    our_dprintf("Initializing client. Unconnected. \n");

    // send syn packet
    ctx->last_send_sequence_num = ctx->initial_sequence_num;
    send_data_packet(sd, ctx, TH_SYN, FALSE, NULL, 0);
    ctx->connection_state = CLIENT_SYN_ACK_WAIT;
    our_dprintf("Sent SYN packet. Go to state CLIENT_SYN_ACK_WAIT \n");

    // wait for syn ack
    unsigned int wait_code = stcp_wait_for_event(sd, NETWORK_DATA, NULL);
    char *recv_syn_ack_packet = (char *)malloc(sizeof(STCPHeader) + STCP_MSS);
    receive_data_packet(sd, ctx, recv_syn_ack_packet, TRUE);
    check_packet_flags((STCPHeader *)recv_syn_ack_packet, (TH_ACK | TH_SYN));
    free(recv_syn_ack_packet);

    // send ack
    send_data_packet(sd, ctx, TH_ACK, TRUE, NULL, 0);
}

static void handle_server_init(mysocket_t sd, context_t *ctx)
{
    // initialize connection state of server
    ctx->connection_state = SERVER_SYN_WAIT;
    our_dprintf("Initializing server. Waiting for client SYN packet. \n");

    // wait for syn
    unsigned int wait_code = stcp_wait_for_event(sd, NETWORK_DATA, NULL);
    char *recv_syn_packet = (char *)malloc(sizeof(STCPHeader) + STCP_MSS);
    receive_data_packet(sd, ctx, recv_syn_packet, FALSE);
    check_packet_flags((STCPHeader *)recv_syn_packet, TH_SYN);
    free(recv_syn_packet);

    // send syn ack
    ctx->last_send_sequence_num = ctx->initial_sequence_num;
    send_data_packet(sd, ctx, (TH_ACK | TH_SYN), TRUE, NULL, 0);
    ctx->connection_state = SERVER_ACK_WAIT;
    our_dprintf("Received SYN packet and sent SYN-ACK packet. Go to sate SERVER_ACK_WAIT \n");

    // wait for ack
    wait_code = stcp_wait_for_event(sd, NETWORK_DATA, NULL);
    char *recv_ack_packet = (char *)malloc(sizeof(STCPHeader) + STCP_MSS);
    receive_data_packet(sd, ctx, recv_ack_packet, TRUE);
    check_packet_flags((STCPHeader *)recv_ack_packet, TH_ACK);
    free(recv_ack_packet);
}

static void handle_app_data(mysocket_t sd, context_t *ctx)
{
    // check the already consumed window size
    size_t consumed_window = (ctx->last_send_sequence_num > ctx->next_expected_sequence_num)
                                 ? ctx->last_send_sequence_num - ctx->next_expected_sequence_num
                                 : 0;

    // while the consumed window size is larger than the current congestion window of the other end
    // host, continue to receive ACK packets and stop any data reception

    if (consumed_window >= ctx->transmit_window_size)
    {
        // our_dprintf("maximum window size %ld bytes, but got %ld bytes consumed. Stop receiving data\n",
        //            ctx->transmit_window_size, consumed_window);
        return;
    }

    // make sure that the consumed window size now is smaller than the maximum congestion window size
    assert(consumed_window < ctx->transmit_window_size);

    // compare the available window size with the maximum data sentable (STCP_MSS),
    // choose the smaller value as the byte of app data to be received
    size_t avail_window = ctx->transmit_window_size - consumed_window;
    size_t max_data_fill = (avail_window < STCP_MSS) ? avail_window : STCP_MSS;
    our_dprintf("largest available window size: %ld; max data fill: %ld\n", avail_window, max_data_fill);

    // create data buffer and receive the amount expected
    char *data_buffer = (char *)malloc(STCP_MSS);
    ssize_t recv_code = stcp_app_recv(sd, data_buffer, max_data_fill);
    if (recv_code == -1)
        our_dprintf("failed receiving data packet\n");
    else
        our_dprintf("received data packet with length %ld\n", recv_code);

    // send out the data buffer to the other end host
    send_data_packet(sd, ctx, 0, FALSE, data_buffer, recv_code);
    free(data_buffer);
}

static void handle_network_data(mysocket_t sd, context_t *ctx)
{
    // create the buffer for receiving network packet
    char *recv_network_packet = (char *)malloc(sizeof(STCPHeader) + STCP_MSS);
    ssize_t recv_code = receive_data_packet(sd, ctx, recv_network_packet, FALSE);
    STCPHeader *recv_network_packet_hdr = (STCPHeader *)recv_network_packet;
    // check the flag bit
    if (recv_network_packet_hdr->th_flags == TH_ACK)
    {
        // if ACK, modify the next sequence number epected
        our_dprintf("received network data packet with ACK flag\n");
        ctx->next_expected_sequence_num = ntohl(recv_network_packet_hdr->th_ack);

        // if it is already waiting for fin acknowledgement, go to fin wait 2 state
        if (ctx->connection_state == CLIENT_FIN_ACK_WAIT)
        {
            our_dprintf("Received ACK packet. Go to FIN_WAIT_2 state. Only able to wait for FIN\n");
            ctx->connection_state = CLIENT_FIN_WAIT_2;
        }
        else if (ctx->connection_state == SERVER_FIN_ACK_WAIT)
        {
            our_dprintf("Received FIN-ACK packet. End connection\n");
            ctx->done = TRUE;
        }
    }
    else if (recv_network_packet_hdr->th_flags == TH_FIN)
    {
        our_dprintf("received network data packet with FIN flag\n");
        // send FIN-ACK
        send_data_packet(sd, ctx, TH_ACK, TRUE, NULL, 0);
        stcp_fin_received(sd);

        // if client in wait 2 state receives TH_FIN,
        // meaning that the other side is also ready to close,
        // set context done bit to TRUE
        if (ctx->connection_state == CLIENT_FIN_WAIT_2)
        {
            our_dprintf("Received FIN request from the other side. End connection\n");
            ctx->done = TRUE;
        }
        else if (ctx->connection_state == CSTATE_ESTABLISHED)
        {
            our_dprintf("Received FIN request from the one side. Becomes the only side active\n");
            ctx->connection_state = SERVER_SEND;
        }
    }
    else if (recv_network_packet_hdr->th_flags == (TH_FIN | TH_ACK))
    {
        ctx->next_expected_sequence_num = ntohl(recv_network_packet_hdr->th_ack);
        if (ctx->connection_state == CLIENT_FIN_ACK_WAIT)
        {
            our_dprintf("received network data packet with FIN-ACK flag. Close connection.\n");
            // send ACK
            send_data_packet(sd, ctx, TH_ACK, TRUE, NULL, 0);
            stcp_fin_received(sd);
            ctx->done = TRUE;
        }
    }
    else
    {
        // if other, send ACK
        unsigned int data_byte = recv_code - sizeof(STCPHeader);
        our_dprintf("received network data packet with data size %d\n", data_byte);
        if (data_byte > 0)
        {
            send_data_packet(sd, ctx, TH_ACK, TRUE, NULL, 0);
            stcp_app_send(sd, recv_network_packet + sizeof(STCPHeader), data_byte);
        }
    }
    free(recv_network_packet);
}

static void handle_app_closing(mysocket_t sd, context_t *ctx)
{
    send_data_packet(sd, ctx, TH_FIN, FALSE, NULL, 0);

    // 2. go to WAIT_FIN_ACK state
    if (ctx->connection_state == CSTATE_ESTABLISHED)
    {
        ctx->connection_state = CLIENT_FIN_ACK_WAIT;
        our_dprintf("Sent FIN packet. Go to CLIENT_FIN_ACK_WAIT state \n");
    }
    else if (ctx->connection_state == SERVER_SEND)
    {
        ctx->connection_state = SERVER_FIN_ACK_WAIT;
        our_dprintf("Sent FIN packet. Go to SERVER_FIN_ACK_WAIT state \n");
    }
}

static ssize_t send_data_packet(mysocket_t sd, context_t *ctx, uint8_t flags, bool_t is_ack, char *data_bytes, ssize_t data_len)
{
    // malloc the size of the packet and input necessary header info
    char *packet = (char *)malloc(sizeof(STCPHeader) + data_len);
    STCPHeader *packet_hdr = (STCPHeader *)packet;
    packet_hdr->th_seq = htonl(ctx->last_send_sequence_num);
    packet_hdr->th_off = TH_OFF;
    packet_hdr->th_flags = flags;
    packet_hdr->th_win = htons(TH_LOCAL_WIN);
    if (is_ack)
        packet_hdr->th_ack = htonl(ctx->last_recv_sequence_num);

    // if it contains data bytes, memcpy it
    if (data_bytes)
        memcpy(packet + sizeof(STCPHeader), data_bytes, data_len);

    // send the packet and check the sent status
    ssize_t send_code = stcp_network_send(sd, (const void *)packet, sizeof(STCPHeader) + data_len, NULL);
    if (send_code == -1)
        our_dprintf("failed sending packet\n");
    else if ((long unsigned int)send_code == sizeof(STCPHeader) + data_len)
        our_dprintf("succeeded sending packet\n");
    else
        our_dprintf("succeeded sending packet but incomplete send, expected %ld sent, but only sent %ld\n", sizeof(STCPHeader) + data_len, send_code);
    free(packet);

    // modify the last sent sequence number based on the sent
    if (flags != TH_ACK)
        ctx->last_send_sequence_num += (data_len > 0) ? data_len : 1;

    // check all current context info
    print_all_sequence_number_and_window(ctx);
    return send_code;
}

static ssize_t receive_data_packet(mysocket_t sd, context_t *ctx, char *buffer, bool_t is_ack)
{
    // receive the packet from network
    ssize_t recv_code = stcp_network_recv(sd, buffer, TH_LOCAL_WIN);

    // check the receiving byte number
    if (recv_code == -1)
        our_dprintf("failed receiving packet\n");
    else
        our_dprintf("received packet with length %ld\n", recv_code);

    // find the number of bytes for the data stream (anything outside the header)
    int data_byte = recv_code - sizeof(STCPHeader);

    // find its header part
    STCPHeader *packet_hdr = (STCPHeader *)buffer;

    // modify the transmit congestion window size based on the packet
    ctx->transmit_window_size = ntohs(packet_hdr->th_win);

    // if duplicate packet --> send again the ACK packet
    if ((packet_hdr->th_seq < ctx->last_recv_sequence_num) && ctx->connection_state >= CSTATE_ESTABLISHED)
    {
        send_data_packet(sd, ctx, TH_ACK, TRUE, NULL, 0);
        return recv_code;
    }

    // modify the last received sequence number based on the current received packet
    ctx->last_recv_sequence_num = (data_byte > 0)
                                      ? ntohl(packet_hdr->th_seq) + data_byte
                                      : ((packet_hdr->th_flags == TH_ACK) ? ntohl(packet_hdr->th_seq) : ntohl(packet_hdr->th_seq) + 1);

    // if it is an ACK packet, modify the next expected sequence number based on the ACK bit
    if (is_ack)
        ctx->next_expected_sequence_num = ntohl(packet_hdr->th_ack);

    // print out all the context info
    print_all_sequence_number_and_window(ctx);
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
    // get the flag bit from the packet header
    uint8_t packet_flags = packet_hdr->th_flags;

    // find the string constant correlating with the two flag bits
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

static void print_all_sequence_number_and_window(context_t *ctx)
{
    our_dprintf("last sequence number sent: %u\n", ctx->last_send_sequence_num);
    our_dprintf("next sequence number expected: %u\n", ctx->next_expected_sequence_num);
    our_dprintf("last sequence number received: %u\n", ctx->last_recv_sequence_num);
    our_dprintf("current window size of the other end host: %ld\n\n", ctx->transmit_window_size);
}
