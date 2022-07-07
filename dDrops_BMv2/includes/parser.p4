#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_DROP_NF 0x081A
#define ETHERTYPE_CPU_HEADER 0x081B
#define ETHERTYPE_dot1q 0x8100

parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_DROP_NF: parse_drop_nf; // notification packet
        ETHERTYPE_CPU_HEADER: parse_cpu_header;
        ETHERTYPE_dot1q : parse_dot1q; 
        ETHERTYPE_IPV4 : parse_ipv4;
        default : ingress;
    }
}
//notification
parser parse_drop_nf {
    extract(sfNotice);
    return parse_dot1q;
}
//cpu header
parser parse_cpu_header {
    extract(cpu_header);
    return parse_dot1q;
}
// Dot1Q.
parser parse_dot1q {
    extract(dot1q);
    return parse_ipv4;
}

// IP.
parser parse_ipv4 {
    extract(ipv4);
    return parse_l4;
}

// TCP / UDP ports.
parser parse_l4 {
    extract(l4_ports);
    return ingress;
}
