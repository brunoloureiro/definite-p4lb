/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_CONTROLLER_REQUEST = 0x1234;
const bit<8> PROTO_TCP = 0x06;
const bit<8> PROTO_UDP = 0x11;

#define MAX_FLOWLETS 64
#define MAX_HASH 1073741823
#define MAX_PORTS 30
#define FLOWLET_TIMEOUT 30000

enum bit<8> controller_op_code_t {
    NO_OP        = 0,
    PULL_BYTES   = 1,
    PULL_PACKETS = 3
}

enum bit<8> controller_response_code_t {
    NO_RESPONSE = 0,
    PULL_OK     = 1
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}

header controller_request_t{
	controller_op_code_t op;
	bit<16> idx;
	bit<48> val0;
	bit<48> val1;
	bit<48> val2;
	bit<48> val3;
	bit<48> val4;
	bit<48> val5;
	bit<48> val6;
	bit<48> val7;
	bit<48> val8;
	bit<48> val9;
}

header controller_response_t{
	controller_op_code_t op;
	bit<16> idx;
	bit<48> val0;
	bit<48> val1;
	bit<48> val2;
	bit<48> val3;
	bit<48> val4;
	bit<48> val5;
	bit<48> val6;
	bit<48> val7;
	bit<48> val8;
	bit<48> val9;
	controller_response_code_t response_code;
}

struct metadata {
	bit<1> use_ecmp;
}


struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
    controller_request_t controller_request;
    controller_response_t controller_response;
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
            TYPE_IPV4: parse_ipv4;
            TYPE_CONTROLLER_REQUEST: parse_controller_request;
            default: accept;
        }
    }

    state parse_controller_request {
    	packet.extract(hdr.controller_request);
    	transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

	register<bit<48>>(MAX_PORTS) bytes_per_port;
	register<bit<48>>(MAX_PORTS) packets_per_port;

	action ipv4_forward(bit<48> nhop_dmac, bit<9> port) {
        hdr.ethernet.dstAddr = nhop_dmac;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        meta.use_ecmp = 0;
    }

	action pull_byte_registers(bit<16> i){
		bit<48> val;

		bytes_per_port.read(val, i+0);
		bytes_per_port.write(i+0, bit<48> 0);
		hdr.controller_response.val0 = val;

		bytes_per_port.read(val, i+1);
		bytes_per_port.write(i+1, bit<48> 0);
		hdr.controller_response.val1 = val;

		bytes_per_port.read(val, i+2);
		bytes_per_port.write(i+2, bit<48> 0);
		hdr.controller_response.val2 = val;

		bytes_per_port.read(val, i+3);
		bytes_per_port.write(i+3, bit<48> 0);
		hdr.controller_response.val3 = val;

		bytes_per_port.read(val, i+4);
		bytes_per_port.write(i+4, bit<48> 0);
		hdr.controller_response.val4 = val;

		bytes_per_port.read(val, i+5);
		bytes_per_port.write(i+5, bit<48> 0);
		hdr.controller_response.val5 = val;

		bytes_per_port.read(val, i+6);
		bytes_per_port.write(i+6, bit<48> 0);
		hdr.controller_response.val6 = val;

		bytes_per_port.read(val, i+7);
		bytes_per_port.write(i+7, bit<48> 0);
		hdr.controller_response.val7 = val;

		bytes_per_port.read(val, i+8);
		bytes_per_port.write(i+8, bit<48> 0);
		hdr.controller_response.val8 = val;

		bytes_per_port.read(val, i+9);
		bytes_per_port.write(i+9, bit<48> 0);
		hdr.controller_response.val9 = val;

		hdr.controller_response.response_code = controller_response_code_t.PULL_OK;
	}

	action pull_packet_registers(bit<16> i){
		bit<48> val;

		packets_per_port.read(val, i+0);
		packets_per_port.write(i+0, bit<48> 0);
		hdr.controller_response.val0 = val;

		packets_per_port.read(val, i+1);
		packets_per_port.write(i+1, bit<48> 0);
		hdr.controller_response.val1 = val;

		packets_per_port.read(val, i+2);
		packets_per_port.write(i+2, bit<48> 0);
		hdr.controller_response.val2 = val;

		packets_per_port.read(val, i+3);
		packets_per_port.write(i+3, bit<48> 0);
		hdr.controller_response.val3 = val;

		packets_per_port.read(val, i+4);
		packets_per_port.write(i+4, bit<48> 0);
		hdr.controller_response.val4 = val;

		packets_per_port.read(val, i+5);
		packets_per_port.write(i+5, bit<48> 0);
		hdr.controller_response.val5 = val;

		packets_per_port.read(val, i+6);
		packets_per_port.write(i+6, bit<48> 0);
		hdr.controller_response.val6 = val;

		packets_per_port.read(val, i+7);
		packets_per_port.write(i+7, bit<48> 0);
		hdr.controller_response.val7 = val;

		packets_per_port.read(val, i+8);
		packets_per_port.write(i+8, bit<48> 0);
		hdr.controller_response.val8 = val;

		packets_per_port.read(val, i+9);
		packets_per_port.write(i+9, bit<48> 0);
		hdr.controller_response.val9 = val;

		hdr.controller_response.response_code = controller_response_code_t.PULL_OK;
	}

	apply{
		if (hdr.controller_request.isValid()){
			switch (hdr.controller_request.op){
				controller_op_code_t.NO_OP: {
					log_msg("Received request from controller with code NO_OP");
				}
				controller_op_code_t.PULL_BYTES: {
					log_msg("Received request from controller with code PULL_BYTES, index {}", {hdr.controller_request.idx})
					pull_byte_registers(hdr.controller_request.idx);
				}
				controller_op_code_t.PULL_PACKETS: {
					log_msg("Received request from controller with code PULL_PACKETS, index {}", {hdr.controller_request.idx})
					pull_packet_registers(hdr.controller_request.idx);
				}
			}
		}
		else if (hdr.ipv4.isValid()){

		}
	}

}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
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
        packet.emit(hdr.ethernet);
        packet.emit(hdr.controller_response);
        packet.emit(hdr.ipv4);
		packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
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
