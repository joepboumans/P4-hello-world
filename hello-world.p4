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

#include "common/headers.p4"
#include "common/util.p4"

struct metadata_t {
} // ---------------------------------------------------------------------------
  // Ingress parser
  // ---------------------------------------------------------------------------
parser SwitchIngressParser(packet_in pkt, out header_t hdr, out metadata_t ig_md,
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
    default:
      reject;
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
  apply { 
    pkt.emit(hdr);
  }
}

control SwitchIngress(
    inout header_t hdr,
    inout metadata_t ig_md,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

  Alpm(number_partitions = 1024, subtrees_per_partition = 2) algo_lpm;
  bit<10> vrf;

  action hit(PortId_t port) {
    ig_intr_tm_md.ucast_egress_port = port; 
  }

  action miss() {
    ig_intr_dprsr_md.drop_ctl = 0x1; // Drop packet
  }
  table forward {
    key = {
      vrf : exact;
      hdr.ipv4.dst_addr : lpm;
    }
    actions = { 
      hit;
      miss;
    }

    const default_action = miss;
    size = 1024;
  }

  action route(mac_addr_t srcMac, mac_addr_t dstMac, PortId_t dst_port) {
    ig_intr_tm_md.ucast_egress_port = dst_port;
    hdr.ethernet.dst_addr = dstMac;
    hdr.ethernet.src_addr = srcMac;
    ig_intr_dprsr_md.drop_ctl = 0x0;
  }
  table alpm_forward {
    key = { 
      vrf : exact;
      hdr.ipv4.dst_addr : lpm;
    }
    actions = { 
      route;
    }

    size = 1024;
    alpm = algo_lpm;
  }
  apply {
    vrf = 10w0;
    forward.apply();
    alpm_forward.apply();

    ig_intr_tm_md.bypass_egress = 1w1;
  }
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         EmptyEgressParser(),
         EmptyEgress(),
         EmptyEgressDeparser()) pipe;

Switch(pipe) main;
