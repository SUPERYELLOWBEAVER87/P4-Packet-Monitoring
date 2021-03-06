/*
Useful references and links while working:
Official Documentation: https://p4.org/p4-spec/docs/P4-16-v1.0.0-spec.html
P4 Github Guide: https://github.com/jafingerhut/p4-guide
P4 Lang Tutorial: https://github.com/p4lang/tutorials/tree/master/exercises
*/


#include <core.p4>
#include <v1model.p4>

/*
Defines constants we will use. 
0x800 defines a IPv4 packet in ethernet header.
6 defines a IPv4 packet utilizing TCP protocol.
*/
const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_TCP = 6;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

/*
Define constant values to use in our program.
*/
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

/*
Defines an ethernet header class.
*/
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

/*
Defines an IPv4 header class.
*/

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
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

/*
Defines a TCP header class.
*/

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

/*
This metadata will contain the has for the flow ID computed by our five variables.
*/
struct metadata {

    bit<32> flowID;
}

/*
Structure that contains all the headers we will be utilizing.
*/
struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

/*
Main parser block:
1. Takes in a packet as input.
2. Outputs headers.
3. Takes in metadata from the packet and outputs it.
4. Takes in standard metadata provided from the switch and outputs it as well.
*/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    /*
    Parser always starts with initial "start" state. Unconditionally transfers to parse_ethernet.
    */
    state start {
        transition parse_ethernet;
    }

    /*
    Extracts ETHERNET headers from the packet parameter provided above.
    Select the ethernet types of the packet and examine it, if it is equivilant to TYPE_IPV4, we transfer to parse_ipv4.
    */
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    /*
    Extracts IPV4 headers from the packet, and unconditionally transitions to the accept state;
    */
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_TCP: parse_tcp;
        }
    }

    /*
    Extracts TCP headers from packet, unconditionally transitions to accept it.
    */
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

/*
Useful Notes:
Timestamps for ingress: https://p4.org/p4-spec/docs/PSA-v1.1.0.html#sec-timestamps
*/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {


    /*
    Action that marks the metadata of the packet to be dropped.
    */
    action drop() {
        mark_to_drop(standard_metadata);
    }
    

    /*
    Computes the flowid which will be used as an index in the register.
    Matching hashes will have the same fields, which identifies them as being a part of the flow.
    */
    action compute_hash(){
        hash(meta.flowID, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.srcAddr,
                                                                hdr.ipv4.dstAddr,
                                                                hdr.ipv4.protocol,
                                                                hdr.tcp.srcPort,
                                                                hdr.tcp.dstPort},
                                                                    (bit<32>)65536);
    }

    /*
    Initialize the register to store all our statistics.
    register<bit size>(Length of array) <name of register>
    */

    register<ip4Addr_t>(65536) r_srcAddr;
    register<ip4Addr_t>(65536) r_dstAddr;
    register<bit<48>>(65536) r_startTime;
    register<bit<48>>(65536) r_endTime;
    register<bit<64>>(65536) r_totalSize;
    register<bit<16>>(65536) r_srcPort;
    register<bit<16>>(65536) r_dstPort;
    register<bit<1>>(65536) r_exist;
    register<bit<48>>(65536) r_duration;

    register<bit<32>>(65536) r_index;
    register<bit<32>>(1) r_counter;
    

    action forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }
    
    table forwarding {
        key = {
            standard_metadata.ingress_port:exact;
        }
        actions = {
            forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    

     
    apply {
        //If the ipv4 header is valid, apply the table.
            forwarding.apply();
            //Compute the hash, store it in the metadata.
            compute_hash();
            //Initialize variable to store current counter variable
            bit<32> counter_value;
            //Counter_value is equal to the value at the 0 index.
            r_counter.read(counter_value, 0);
            //Record the flow ID of the current packet with the counter.
            r_index.write(counter_value, meta.flowID);

            //Initialize variable to store value
            bit<1> exist_value;
            //Exist_value is equal to the value at flowID
            r_exist.read(exist_value, meta.flowID);

            //If the value is still equal to 0 at the flow ID, then the flow has not been registered.
            if (exist_value == 0){
                r_srcAddr.write(meta.flowID, hdr.ipv4.srcAddr);
                r_dstAddr.write(meta.flowID, hdr.ipv4.dstAddr);
                r_startTime.write(meta.flowID, standard_metadata.ingress_global_timestamp);
                r_endTime.write(meta.flowID, standard_metadata.ingress_global_timestamp);
                bit<64> temporary = (bit<64>) hdr.ipv4.totalLen;
                r_totalSize.write(meta.flowID, temporary);
                r_srcPort.write(meta.flowID, hdr.tcp.srcPort);
                r_dstPort.write(meta.flowID, hdr.tcp.dstPort);
                r_exist.write(meta.flowID, 1);
                //Increment the counter variable by adding 1 to it
                r_counter.write(0, counter_value + 1);
            }
            //Otherwise if the value is not default, it has been set. This is a registered flow.
            else{
                //End time is the new start time
                r_endTime.write(meta.flowID, standard_metadata.ingress_global_timestamp);
                //Increment total length register value
                bit<64> old_size;
                r_totalSize.read(old_size, meta.flowID);
                bit<48> initial_startTime;
                r_startTime.read(initial_startTime, meta.flowID);
                r_duration.write(meta.flowID, standard_metadata.ingress_global_timestamp - initial_startTime);
                r_totalSize.write(meta.flowID, old_size + (bit<64>) hdr.ipv4.totalLen);
            }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
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
//MyVerifyChecksum(),
MyIngress(),
MyEgress(),
//MyComputeChecksum(),
MyDeparser()
) main;
