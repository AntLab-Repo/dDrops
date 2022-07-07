/**
 *
 * header.p4
 * 
 */

/*===========================================
=            Forwarding Headers.            =
===========================================*/
header_type ethernet_t {
        fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}
header ethernet_t ethernet;
header_type dot1q_t {
    fields {
        prio : 3;
        id : 1;
        vlan : 12;
	type : 16;
    }
}
header dot1q_t dot1q;

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16; // here
        srcAddr : 32;
        dstAddr: 32;
    }
}
header ipv4_t ipv4;
header_type l4_ports_t {
    fields {
        ports : 32;
    }
}
header l4_ports_t l4_ports;

header_type sfNotice_t {
    fields {
        startPId : 12;
        endPId : 12;
        type : 8;
    }
}
header sfNotice_t sfNotice;

header_type cpu_header_t {
    fields {
        srcAddr : 32;
        dstAddr : 32;
        ports : 32;
        vlan : 12;
        id : 4;
        protocol : 8;
    }
}
header cpu_header_t cpu_header;
