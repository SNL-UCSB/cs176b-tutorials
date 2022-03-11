/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define REGISTER_WIDTH 32
#define REGISTER_ENTRIES 65536
#define REDUCE_TH 10


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    bit<32>   srcAddr;
    bit<32>   dstAddr;
}

header tcp_t {
    bit<16>    sPort;
    bit<16>    dPort;
    bit<32>    seqNo;
    bit<32>    ackNo;
    bit<4>     dataOffset;
    bit<4>     res;
    bit<8>     flags;
    bit<16>    window;
    bit<16>    checksum;
    bit<16>    urgentPtr;
}

header out_header_t {
    bit<16>    qid;
    bit<32>    ipv4_dstIP;
    bit<16>    index;
}

struct metadata {
    bit<1>    success;
    bit<32> ipv4_dstIP;
    bit<32>  value;
    bit<16>  index;
}

struct headers {
    out_header_t out_header;
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
	    0x6: parse_tcp;
	    default: accept;
	}
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
	transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(bit<48> dstAddr, bit<9> port) {
        standard_metadata.egress_spec = port;
	hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    table ipv4_lpm {
        key = {
	    hdr.ipv4.dstAddr: lpm;
	}
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    action map() {
        meta.ipv4_dstIP = hdr.ipv4.dstAddr;
    }

    register<bit<REGISTER_WIDTH>>(REGISTER_ENTRIES) reduce_reg;
    action reduce() {
	hash(meta.index, HashAlgorithm.crc16, (bit<32>)0, {meta.ipv4_dstIP}, (bit<32>)REGISTER_ENTRIES);
	reduce_reg.read(meta.value, (bit<32>)meta.index);
	meta.value = meta.value + 1;
	reduce_reg.write((bit<32>)meta.index, meta.value);
    }

    action clone_i2e() {
        clone3(CloneType.I2E, 432, {meta.ipv4_dstIP, meta.index});
    }
    
    apply {
        if (!hdr.tcp.isValid()) {
	    meta.success = 0;
	} else {
            meta.success = 1;
	}
	if (meta.success == 0 || hdr.tcp.flags != 2) {
	    meta.success = 0;
	}
	if (meta.success == 1) {
	    map();
	}
	if (meta.success == 1) {
	    reduce();
            if (meta.value == REDUCE_TH) {
	        clone_i2e();
            } else {
	        meta.success = 0;
	    }
	}
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    action add_out_header() {
        hdr.out_header.setValid();
	hdr.out_header.qid = 4;
	hdr.out_header.ipv4_dstIP = meta.ipv4_dstIP;
	hdr.out_header.index = meta.index;
    }
    
    apply {
        if (standard_metadata.instance_type == 1) {
	    add_out_header();
	} else {
	    hdr.out_header.setInvalid();
	}
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.out_header);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
	packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
