/*******************************************************************************
 *  INTEL CONFIDENTIAL
 *
 *  Copyright (c) 2021 Intel Corporation
 *  All Rights Reserved.
 *
 *  This software and the related documents are Intel copyrighted materials,
 *  and your use of them is governed by the express license under which they
 *  were provided to you ("License"). Unless the License provides otherwise,
 *  you may not use, modify, copy, publish, distribute, disclose or transmit
 *  this software or the related documents without Intel's prior written
 *  permission.
 *
 *  This software and the related documents are provided as is, with no express
 *  or implied warranties, other than those that are expressly stated in the
 *  License.
 ******************************************************************************/

#include <core.p4>
#if __TARGET_TOFINO__ == 3
#include <t3na.p4>
#elif __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#define CMS_ENTRIES 65536
#define CMS_BIT_WIDTH 32
#define PACKET_THRESHOLD 2
#define DELAY_THRESHOLD 100000 // delay in ns

typedef bit<32> time_t;

struct metadata_t {
  bit<16> flowInex_one;
  bit<16> flowInex_two;
  bit<32> count_one;
  bit<32> count_two;
  bit<32> count_min;
  bit<18> cur_time;
  bit<1> window_flag;
  bit<32> delay_threshold;
}

#include "common/headers.p4"
#include "common/util.p4"

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser
SwitchIngressParser(packet_in pkt, out header_t hdr, out metadata_t ig_md,
                    out ingress_intrinsic_metadata_t ig_intr_md) {

  TofinoIngressParser() tofino_parser;

  state start {
    tofino_parser.apply(pkt, ig_intr_md);
    transition parse_ethernet;
  }

  state parse_ethernet {
    pkt.extract(hdr.ethernet);
    transition select(hdr.ethernet.ether_type) {
    ETHERTYPE_IPV4:
      parse_ipv4;
    // ETHERTYPE_VLAN : parse_vlan;
    default:
      accept;
    }
  }

  state parse_ipv4 {
    pkt.extract(hdr.ipv4);
    transition select(hdr.ipv4.protocol) {
    IP_PROTOCOLS_UDP:
      parse_udp;
    IP_PROTOCOLS_TCP:
      parse_tcp;
    default:
      accept;
    }
  }

  state parse_tcp {
    pkt.extract(hdr.tcp);
    transition accept;
  }

  state parse_udp {
    pkt.extract(hdr.udp);
    transition accept;
  }
}
// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
    packet_out pkt, inout header_t hdr, in metadata_t ig_md,
    in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
  Checksum() ipv4_checksum;
  apply {
    hdr.ipv4.hdr_checksum = ipv4_checksum.update(
        {hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.total_len,
         hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.frag_offset,
         hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.src_addr,
         hdr.ipv4.dst_addr});
    pkt.emit(hdr);
  }
}
