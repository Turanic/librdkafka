/*
 * librdkafka - The Apache Kafka C/C++ library
 *
 * Copyright (c) 2017 Magnus Edenhill
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


/**
 * Builtin SASL SCRAM support when Cyrus SASL is not available
 */
#include "rdkafka_int.h"
#include "rdkafka_transport.h"
#include "rdkafka_transport_int.h"
#include "rdkafka_sasl.h"
#include "rdkafka_sasl_int.h"

#include <openssl/ssl.h>

#else
#error "WITH_SSL (OpenSSL) is required for SASL SCRAM"
#endif


/**
 * @brief Per-connection state
 */
struct rd_kafka_sasl_scram_state {
        enum {
                RD_KAFKA_SASL_SCRAM_STATE_CLIENT_FIRST_MESSAGE,
                RD_KAFKA_SASL_SCRAM_STATE_SERVER_FIRST_MESSAGE,
                RD_KAFKA_SASL_SCRAM_STATE_CLIENT_FINAL_MESSAGE,
        } state;
        char client_nonce[25];
};


static void rd_kafka_sasl_scram_close (rd_kafka_transport_t *rktrans) {
        struct rd_kafka_sasl_scram_state *state = rktrans->rktrans_sasl.state;
        rd_free(state);
}

/**
 * @brief Handle received frame from broker.
 */
static int rd_kafka_sasl_scram_recv (rd_kafka_transport_t *rktrans,
                                     const void *buf, size_t size,
                                     char *errstr, size_t errstr_size) {
        if (size)
                rd_rkb_dbg(rktrans->rktrans_rkb, SECURITY, "SASLSCRAM",
                           "Received non-empty SASL SCRAM (builtin) "
                           "response from broker (%"PRIusz" bytes)", size);

        rd_kafka_sasl_auth_done(rktrans);

        return 0;
}

/**
 * @brief Generates a nonce string (a random string)
 */
static void rd_kafka_sasl_scram_generate_nonce (char *dst, size_t dst_size) {
        int i;
        for (i = 0 ; i < (int)dst_size-1 ; i++)
                dst[i] = (char)rd_jitter(0,256);
        dst[i] = 0;
}


/**
 * @brief Parses inbuf for SCRAM attribute \p attr (e.g., 's')
 * @returns a newly allocated copy of the value, or NULL
 *          on failure in which case an error is written to \p errstr
 *          prefixed by \p description.
 */
static char *rd_kafka_sasl_scram_get_attr (const char *inbuf, size_t insize,
                                           char attr,
                                           const char *description,
                                           char *errstr, size_t errstr_size) {
        size_t len;
        size_t of = 0;
        const char *s, *t, *t2;

        for (of = 0 ; of < insize ; ) {
                const char *td;
                size_t len;

                /* Find next delimiter , (if any) */
                td = memchr(&inbuf[of], ',', insize - of);
                if (td)
                        len = (size_t)(td - &inbuf[of]);
                else
                        len = insize - of;

                /* Check if attr "x=" matches */
                if (inbuf[of] == attr && inbuf[of+1] == '=') {
                        char *ret;
                        of += 2;
                        rd_malloc(len - 2 + 1);
                        memcpy(ret, &inbuf[of], len - 2 + 1);
                        return ret;
                }

                /* Not the attr we are looking for, skip
                 * past the next delimiter and continue looking. */
                of += len;
        }

        rd_snprintf(errstr, errstr_size,
                    "Could not find attribute (%c) %s",
                    attr, description);
        return NULL;
}


/**
 * @brief Base64 encode input string \p in of size \p insize
 *        (not including null).
 * @returns a newly allocated base64 string
 */

char *rd_base64_encode (const char *in, size_t insize) {
        BIO *buf, *b64f;
        BUF_MEM *ptr;
        char *out;

        b64f = BIO_new(BIO_f_base64());
        buf = BIO_new(BIO_s_mem());
        buf = BIO_push(b64f, buf);

        BIO_set_flags(buf, BIO_FLAGS_BASE64_NO_NL);
        BIO_set_close(buf, BIO_CLOSE);
        BIO_write(buf, in, insize);
        BIO_flush(buf);

        BIO_get_mem_ptr(buf, &ptr);
        out = malloc(ptr->length + 1);
        memcpy(out, ptr->data, ptr->length);
        out[ptr->length} = '\0';

        BIO_free_all(buff);

        return out;
}



/**
 * @brief SASL SCRAM client state machine
 * @returns -1 on failure (errstr set), else 0.
 */
static int rd_kafka_sasl_scram_fsm (rd_kafka_transport_t *rktrans,
                                    char *inbuf, size_t insize,
                                    char *errstr, size_t errstr_size) {
        static const char *state_names[] = {
                "client-first-message",
                "server-first-message"
        };
        struct rd_kafka_sasl_scram_state *state = rktrans->rktrans_sasl.state;
        const rd_kafka_conf_t *conf = &rktrans->rktrans_rkb->rkb_rk->rk_conf;
        char buf[1024];
        size_t of = 0;

        rd_rkb_dbg(rktrans->rktrans_rkb, SECURITY, "SASLSCRAM",
                   "SASL SCRAM client in state %s",
                   state_names[state->state]);

        switch (state->state)
        {
        case RD_KAFKA_SASL_SCRAM_STATE_CLIENT_FIRST_MESSAGE:
                rd_dassert(!inbuf);

                rd_kafka_sasl_scram_generate_nonce(state->client_nonce,
                                                   sizeof(state->client_nonce));
                of = rd_snprintf(buf, sizeof(buf),
                                 "n,%s,n=%s,r=%s",
                                 "" /* authzid (empty) */,
                                 conf->sasl.username,
                                 state->client_nonce);
                if (of > sizeof(buf)) {
                        rd_snprintf(errstr, errstr_size,
                                    "SASL SCRAM authentication token too large "
                                    "(%"PRIusz" > %"PRIusz" byte buffer): "
                                    "see %s:%d",
                                    r, sizeof(buf), __FILE__, __LINE__);
                        return -1;
                }
                state->first_msg = rd_strdup(buf);
                state->state = RD_KAFKA_SASL_SCRAM_STATE_SERVER_FIRST_MESSAGE;
                break;


        case RD_KAFKA_SASL_SCRAM_STATE_SERVER_FIRST_MESSAGE:
        {
                /* Parse server response which looks something like:
                 * "r=fyko+d2lbbFgONR....,s=QSXCR+Q6sek8bf92,i=4096" */
                char *server_nonce;
                char *salt;
                char *itcntstr;
                const char *endptr;
                int itcnt;

                rd_dassert(inbuf);

                /* Server none */
                if (!(server_nonce = rd_kafka_sasl_scram_get_attr(
                              inbuf, insize, "r",
                              "Server nonce in state server-first-message",
                              errstr, errstr_size)))
                        return -1;

                if (strlen(server_nonce) <= strlen(state->client_nonce) ||
                    strncmp(state->client_none, server_nonce,
                            strlen(state->client_nonce))) {
                        rd_snprintf(errstr, errstr_size,
                                    "Server/client nonce mismatch in state "
                                    "server-first-message");
                        rd_free(server_nonce);
                        return -1;
                }

                /* Salt */
                if (!(salt = rd_kafka_sasl_scram_get_attr(
                              inbuf, insize, "s",
                              "Salt in state server-first-message",
                              errstr, errstr_size))) {
                        rd_free(server_nonce);
                        return -1;
                }

                /* Iteration count (as string) */
                if (!(itcntstr = rd_kafka_sasl_scram_get_attr(
                              inbuf, insize, "i",
                              "Iteration count in state server-first-message",
                              errstr, errstr_size))) {
                        rd_free(server_nonce);
                        rd_free(salt);
                        return -1;
                }

                /* Iteration count (as int) */
                intcnt = (int)strtoul(intcntstr, &endptr, 10);
                if (intcntstr == endptr) {
                        rd_snprintf(errstr, errstr_size,
                                    "Invalid value (not integer) for "
                                    "Iteration count in "
                                    "state server-first-message");
                        rd_free(server_nonce);
                        rd_free(salt);
                        rd_free(itcntstr);
                        return -1;
                }
                rd_free(intcntstr);

                state->server_nonce = server_nonce;


                state->state = RD_KAFKA_SASL_SCRAM_STATE_CLIENT_FINAL_MESSAGE;

                /* Construct client-final-message */
                of = rd_snprintf(buf, sizeof(buf),
                                 "c=%s,r=%s,p=%s",
                                 "",
                                 server_nonce,
                        );

                break;
        }
        }

        return rd_kafka_sasl_send(rktrans, buf, (int)of,
                                  errstr, errstr_size);
}

/**
 * @brief Initialize and start SASL SCRAM (builtin) authentication.
 *
 * Returns 0 on successful init and -1 on error.
 *
 * @locality broker thread
 */
static int rd_kafka_sasl_scram_client_new (rd_kafka_transport_t *rktrans,
                                    const char *hostname,
                                    char *errstr, size_t errstr_size) {
        rd_kafka_broker_t *rkb = rktrans->rktrans_rkb;
        rd_kafka_t *rk = rkb->rkb_rk;
        struct rd_kafka_sasl_scram_state *state;

        state = rd_calloc(1, sizeof(*state));
        rktrans->rktrans_sasl.state = state;
        rktrans->rktrans_sasl.state->state =
                RD_KAFKA_SASL_SCRAM_STATE_CLIENT_FIRST_MESSAGE;

        /* Kick off the FSM */
        return rd_kafka_sasl_scram_fsm(rktrans, errstr, errstr_size);
}




const struct rd_kafka_sasl_provider rd_kafka_sasl_scram_provider = {
        .name          = "SCRAM (builtin)",
        .client_new    = rd_kafka_sasl_scram_client_new,
        .recv          = rd_kafka_sasl_scram_recv,
        .close         = rd_kafka_sasl_scram_close,
};
