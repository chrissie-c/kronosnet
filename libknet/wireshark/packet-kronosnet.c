/* packet-kronosnet.c
 * Routines for the Kronosnet (kronosnet) protocol used by corosync
 * corosync packets are NOT decoded by this dissector
 * (c) 2026 Red Hat etc....
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

//#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <wsutil/file_util.h>

#include "../libknet.h"
#include "../crypto.h"
#include "packet-kronosnet.h"

void proto_register_kronosnet(void);
void proto_reg_handoff_kronosnet(void);


WS_DLL_PUBLIC_DEF const char plugin_version[] = "1.0";
WS_DLL_PUBLIC_DEF const int plugin_want_major = 4;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = 6;


#define PROTO_TAG_KRONOSNET      "Kronosnet"    /*!< Definition of kronosnet Protocol */
#define PORT 5405           /* Not IANA registered */


/**
 * @addtogroup messageids kronosnet Message ID:s
 * Message ID:s of the kronosnet protocol
 */
/**@{*/
#define KRONOSNET_HEADER_TYPE_DATA        0x00 /* !< Message ID definition: pure data packet */

#define KRONOSNET_HEADER_TYPE_PING        0x81 /* !< Message ID definition: heartbeat */
#define KRONOSNET_HEADER_TYPE_PONG        0x82 /* !< Message ID definition: reply to heartbeat */
#define KRONOSNET_HEADER_TYPE_PMTUD       0x83 /* !< Message ID definition: Used to determine Path MTU */
#define KRONOSNET_HEADER_TYPE_PMTUD_REPLY 0x84 /* !< Message ID definition: reply from remote host */

/**
 * @addtogroup protocols Protocol Variables
 * Protocol variables.
 */
/**@{*/
static int proto_kronosnet;
static dissector_handle_t kronosnet_handle;
static int hf_kronosnet_packet_type;
static int ett_kronosnet;
static int ett_kronosnet_data;
static int ett_kronosnet_ping;
static int ett_kronosnet_pmtu;
static const char *kronosnet_private_key_file;
static const char *kronosnet_crypto_cipher;
static const char *kronosnet_crypto_hash;
static const char *private_key;

static int crypto_initialised = 0;
static knet_handle_t knet_h;

// Header fields
static int hf_kh_version; /* this pckt format/version */
static int hf_kh_type;    /* from above defines. Tells what kind of pckt it is */
static int hf_kh_node;    /* host id of the source host for this pckt */
static int hf_kh_max_ver; /* max version of the protocol supported by this node */
static int hf_kh_pad1;    /* make sure to have space in the header to grow features */

static int hf_khp_data_seq_num;
static int hf_khp_data_compress;
static int hf_khp_data_pad1;
static int hf_khp_data_bcast;
static int hf_khp_data_frag_num;
static int hf_khp_data_channel;
static int hf_khp_ping_link;
static int hf_khp_ping_time1;
static int hf_khp_ping_time2;
static int hf_khp_ping_time3;
static int hf_khp_ping_time4;
static int hf_khp_ping_seq_num;
static int hf_khp_ping_timed;
static int hf_khp_pmtud_link;
static int hf_khp_pmtud_size;

/**@}*/

/**
 * @addtogroup headerfields Dissector Header Fields
 * Header fields of the kronosnet datagram
 */
/* *@{*/


static const value_string knet_packet_type_names[] = {
    { KRONOSNET_HEADER_TYPE_DATA,        "Data"        },
    { KRONOSNET_HEADER_TYPE_PING,        "Ping"        },
    { KRONOSNET_HEADER_TYPE_PONG,        "Ping Reply"  },
    { KRONOSNET_HEADER_TYPE_PMTUD,       "PMTU Check"  },
    { KRONOSNET_HEADER_TYPE_PMTUD_REPLY, "PMTU Reply"  },
    { 0,                    NULL                  }
};


static int dissect_data_v1(proto_tree *pt, tvbuff_t *tvb, int offset)
{
    proto_tree *data_tree = proto_tree_add_subtree(pt, tvb, offset, 9, ett_kronosnet_data, NULL, "Data");

    proto_tree_add_item(data_tree, hf_khp_data_seq_num, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(data_tree, hf_khp_data_compress, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(data_tree, hf_khp_data_pad1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(data_tree, hf_khp_data_bcast, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(data_tree, hf_khp_data_frag_num, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(data_tree, hf_khp_data_channel, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    return offset;
}

static int dissect_ping_v1(proto_tree *pt, tvbuff_t *tvb, int offset, char *name)
{
    proto_tree *ping_tree = proto_tree_add_subtree(pt, tvb, offset, 9, ett_kronosnet_ping, NULL, name);

    proto_tree_add_item(ping_tree, hf_khp_ping_link, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ping_tree, hf_khp_ping_time1, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(ping_tree, hf_khp_ping_time2, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(ping_tree, hf_khp_ping_time3, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(ping_tree, hf_khp_ping_time4, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(ping_tree, hf_khp_ping_seq_num, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(ping_tree, hf_khp_ping_timed, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    return offset;
}

static int dissect_pmtud_v1(proto_tree *pt, tvbuff_t *tvb, int offset, char *name)
{
    proto_tree *pmtu_tree = proto_tree_add_subtree(pt, tvb, offset, 9, ett_kronosnet_pmtu, NULL, name);

    proto_tree_add_item(pmtu_tree, hf_khp_pmtud_link, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(pmtu_tree, hf_khp_pmtud_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

static int read_key_file(packet_info *pinfo)
{
    FILE *fp;
    long fsize = 0;
    char *buf;

    fp = ws_fopen(kronosnet_private_key_file, "rb");
    if (fp != NULL) {
        fseek(fp, 0, SEEK_END);
        fsize = ftell(fp);
        if (fsize == -1L) {
            fclose(fp);
            return -1;
        }
        fseek(fp, 0, SEEK_SET);

        buf = (char*)wmem_alloc(pinfo->pool, fsize + 1);
        if (fread(buf, 1, fsize, fp) != (size_t)fsize) {
            fclose(fp);
            return -1;
        }
        buf[fsize] = '\0';
        fclose(fp);
    }
    private_key = buf;
    return fsize;
}

/**
 * dissect_kronosnet is the dissector which is called
 * by Wireshark when kronosnet UDP packets are captured.
 *
 * @param tvb the buffer to the data
 * @param pinfo the packet info structure
 * @param tree the parent tree where the dissected data is going to be inserted
 *
 */
static int
dissect_kronosnet(tvbuff_t *tvb, packet_info *pinfo, __attribute__((unused)) proto_tree *tree, void* data _U_)
{
    tvbuff_t *next_tvb = NULL;

    /* Only decrypt if we have ALL of the information we need */
    if (kronosnet_private_key_file &&
        kronosnet_crypto_cipher &&
        kronosnet_crypto_hash) {
        if (!crypto_initialised) {
            // Init openssl
            knet_h = knet_handle_new(0, 0, 0, 0);
            if (knet_h) {
                ws_warning("Kronsnet: Failed to get knet_handle");
            }
            struct knet_handle_crypto_cfg ccfg;
            strcpy(ccfg.crypto_model, "openssl");
            strcpy(ccfg.crypto_cipher_type, kronosnet_crypto_hash);
            strcpy(ccfg.crypto_cipher_type, kronosnet_crypto_cipher);
            ccfg.private_key_len = read_key_file(pinfo);
            if (ccfg.private_key_len > 0) {
                memcpy(ccfg.private_key, private_key, ccfg.private_key_len);
                if (knet_handle_crypto_set_config(knet_h, &ccfg, 0) != 0) {
                    ws_warning("Kronsnet: Failed to init crypto");
                }
            } else {
                ws_warning("Kronsnet: Failed to read private key");
            }
            crypto_initialised = 1;
        }
        // decrypt packet and reset tvb etc
        int len = tvb_captured_length_remaining(tvb, 0);
        unsigned char *newbuf = (unsigned char*)wmem_alloc(pinfo->pool, len);
        ssize_t outlen = len;
        int res = crypto_authenticate_and_decrypt(knet_h,
                                                  tvb_memdup(pinfo->pool, tvb, 0, -1), len,
                                                  newbuf, &outlen);
        if (!res) {
            ws_warning("Kronsnet: Failed to decrypt packet");
        } else {
            next_tvb = tvb_new_child_real_data(tvb, newbuf, len, outlen);
        }
    }

    if (next_tvb == NULL) {
        return 0;
    }


    int offset = 0;
    int type = 0;
    int version = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "KRONOSNET");
    /* Clear the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    // Might need to change this to allow us to encapsulate corosync (if that ever happens)
    proto_item *ti = proto_tree_add_item(tree, proto_kronosnet, next_tvb, 0, -1, ENC_NA);

    proto_tree *kronosnet_tree = proto_item_add_subtree(ti, ett_kronosnet);
    proto_tree_add_item(kronosnet_tree, hf_kronosnet_packet_type, next_tvb, 0, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(kronosnet_tree, hf_kh_version, next_tvb, offset, 1, ENC_BIG_ENDIAN);
    version = tvb_get_uint8(next_tvb, offset);
    offset += 1;
    proto_tree_add_item(kronosnet_tree, hf_kh_type, next_tvb, offset, 1, ENC_BIG_ENDIAN);
    type = tvb_get_uint8(next_tvb, offset);
    offset += 1;
    proto_tree_add_item(kronosnet_tree, hf_kh_node, next_tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(kronosnet_tree, hf_kh_max_ver, next_tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(kronosnet_tree, hf_kh_pad1, next_tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (version == 1) {
        switch (type) {
            case KRONOSNET_HEADER_TYPE_DATA:
                offset = dissect_data_v1(kronosnet_tree, next_tvb, offset);
                break;
            case KRONOSNET_HEADER_TYPE_PING:
                offset = dissect_ping_v1(kronosnet_tree, next_tvb, offset, "Ping");
                break;
            case KRONOSNET_HEADER_TYPE_PONG:
                offset = dissect_ping_v1(kronosnet_tree, next_tvb, offset, "Pong");
                break;
            case KRONOSNET_HEADER_TYPE_PMTUD:
                offset = dissect_pmtud_v1(kronosnet_tree, next_tvb, offset, "pMTUd");
                break;
            case KRONOSNET_HEADER_TYPE_PMTUD_REPLY:
                offset = dissect_pmtud_v1(kronosnet_tree, next_tvb, offset, "pMTUd Reply");
                break;
        }
    }

    return tvb_captured_length(next_tvb);
}
/**
 * proto_register_kronosnet registers our kronosnet protocol,
 * headerfield- and subtree-array to Wireshark.
 *
 */
void
proto_register_kronosnet(void)
{
    module_t *kronosnet_module;

    static hf_register_info hf[] = {
        // First entry is needed but not sure what it does
        { &hf_kronosnet_packet_type,
          { "Kronosnet Packet Type", "kronosnet.type",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_kh_version,
          { "kronosnet version", "kronosnet.version",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_kh_type,
          { "Kronosnet packet type", "kronosnet.type",
            FT_UINT8, BASE_DEC,
            VALS(knet_packet_type_names), 0x0,
            NULL, HFILL }
        },
        { &hf_kh_node,
          { "Kronosnet node id", "kronosnet.nodeid",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_kh_max_ver,
          { "kronosnet max version", "kronosnet.max_version",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_kh_pad1,
          { "Kronosnet pad1", "kronosnet.pad1",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_data_seq_num,
          { "Kronosnet data seq_num", "kronosnet.data.seq_num",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_data_compress,
          { "Kronosnet data compress", "kronosnet.data.compress",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_data_pad1,
          { "Kronosnet data pad1", "kronosnet.data.pad1",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_data_bcast,
          { "Kronosnet data bcast", "kronosnet.data.bcast",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_data_frag_num,
          { "Kronosnet data frag_num", "kronosnet.data.frag_num",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_data_channel,
          { "Kronosnet data channel", "kronosnet.data.channel",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_ping_link,
          { "Kronosnet ping/pong link", "kronosnet.pingpong.link",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_ping_time1,
          { "Kronosnet ping/pong time1", "kronosnet.pingpong.time1",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_ping_time2,
          { "Kronosnet ping/pong time2", "kronosnet.pingpong.time2",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_ping_time3,
          { "Kronosnet ping/pong time3", "kronosnet.pingpong.time3",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_ping_time4,
          { "Kronosnet ping/pong time4", "kronosnet.pingpong.time4",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_ping_seq_num,
          { "Kronosnet ping/pong seq_num", "kronosnet.pingpong.seq_num",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_ping_timed,
          { "Kronosnet ping/pong timed", "kronosnet.pingpong.timed",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_pmtud_link,
          { "Kronosnet pMTU link", "kronosnet.pmtu.link",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_khp_pmtud_size,
          { "Kronosnet pMTU size", "kronosnet.pmtu.size",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_kronosnet,
        &ett_kronosnet_data,
        &ett_kronosnet_ping,
        &ett_kronosnet_pmtu,
    };


    /* Register protocols */
    proto_kronosnet = proto_register_protocol ("kronosnet Protocol", "KRONOSNET", "kronosnet");
    proto_register_field_array(proto_kronosnet, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    kronosnet_handle = register_dissector_with_description(
        "kronosnet",
        "Kronosnet protocol",
        dissect_kronosnet,
        proto_kronosnet);

    /* Prefs to get encryption parameters */
    kronosnet_module = prefs_register_protocol(proto_kronosnet, NULL);
    prefs_register_filename_preference(kronosnet_module, "private_key_file", "Private key filename",
                                     "File containting key used to encryption",
                                       &kronosnet_private_key_file, false);
    prefs_register_string_preference(kronosnet_module, "crypto_cipher", "Crypto Cipher",
                                     "encrpytion cipher",
                                     &kronosnet_crypto_cipher);
    prefs_register_string_preference(kronosnet_module, "crypto_hash", "Crypto Hash",
                                     "HMAC authentication type",
                                     &kronosnet_crypto_hash);

}

/**
 * proto_reg_handoff_kronosnet registers our kronosnet dissectors to Wireshark
 *
 */
void
proto_reg_handoff_kronosnet(void)
{
    dissector_add_uint_with_preference("udp.port", PORT, kronosnet_handle);
}


WS_DLL_PUBLIC_DEF void plugin_register(void)
{
    static proto_plugin plug_kronosnet;

    plug_kronosnet.register_protoinfo = proto_register_kronosnet;
    plug_kronosnet.register_handoff = proto_reg_handoff_kronosnet;
    proto_register_plugin(&plug_kronosnet);
}


/*
* Editor modelines - https://www.wireshark.org/tools/modelines.html
*
* Local variables:
* c-basic-offset: 4
* tab-width: 8
* indent-tabs-mode: nil
* End:
*
* ex: set shiftwidth=4 tabstop=8 expandtab:
* :indentSize=4:tabSize=8:noTabs=true:
*/
