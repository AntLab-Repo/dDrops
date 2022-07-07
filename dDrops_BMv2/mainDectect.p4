/**
 *
 * mainDropDetect.p4
 * 
 */
#include "includes/headers.p4"
#include "includes/parser.p4"

#define BUFFER_BIT 12
#define PORT_NUM_1 4
#define BUFFER_SIZE_1 4096

#define ETHERTYPE_DROP_NF 0x081A
#define ETHERTYPE_CPU_HEADER 0x081B
#define ETHERTYPE_ACTIVE_ID 0x081C    
#define ETHERTYPE_dot1q 0x8100

#define N_IN 1024
##define N_IN 60
#define BLOCK_SIZE 32  

#define BLOCK_NUM  128  

#define BLOCK_BIT 7
#define OFFSET_BIT 5

#define OFFSET_SIZE 31

header_type port_t {
    fields {
        in_id: 12;
	out_id: 12;
    }
}
metadata port_t port;

header_type pointer_t {
    fields {
        qfront: 12;        
        qrear: 12;
        qrearo: 12;
    }
}
metadata pointer_t pointer;

header_type sfInfoKey_t {
    fields {
        startPId : 12;
        endPId : 12;
	top : 7 ;
        vlan : 12;	

	type : 8;
	freecnt :  6;  
	currentpos : 12 ; 
        fpos : 12 ;//
	free_logic_id : 12 ;
	free_actual_id : 12 ;
	
	in_cnt : 12 ; 
	out_cnt : 12 ;
	

	outpktid : 12;//out vlan id
	block_logic_out_id : 12 ;
	block_actual_out_id : 12 ;
	actual_out_id : 12 ;
	Offset_2 : 12 ;
	out_actual_h :12 ;
	

	qfstart : 12;
	qfend : 12;
	drop_block_logic_id : 12 ;
	drop_block_actual_id : 12;
	drop_actual_id : 12 ;//actual id
	drop_actual_h : 12 ;
	Offset_1 : 12 ; 
	
	
	next_block_actual_id : 12 ;
	next_logic_block_id : 12;
    }
}
metadata sfInfoKey_t sfInfoKey;

control ingress {
	process_1();
}
control egress {
	//process_2();
}


#define CPU_MIRROR_SESSION_ID                  250
field_list mirror_list_1 {
    sfInfoKey.drop_actual_id;
}

action do_copy_to_cpu() {
    clone_egress_pkt_to_egress(CPU_MIRROR_SESSION_ID, mirror_list_1);
}
table copy_to_cpu {
    actions {do_copy_to_cpu;}
}


action ainPortPktId() {  
    modify_field(sfInfoKey.endPId, dot1q.vlan-1);
    register_read(sfInfoKey.startPId, rinPortPktId, port.in_id);
    register_write(rinPortPktId, port.in_id, dot1q.vlan + 1);
    register_read(sfInfoKey.in_cnt, rin_cnt, port.in_id);
    register_write(rin_cnt, port.in_id, sfInfoKey.in_cnt + 1);
    modify_field(sfInfoKey.in_cnt, sfInfoKey.in_cnt+1);
}
table tiDetectDrop{
      actions {ainPortPktId;}
}

action set_egr(egress_spec) {
    modify_field(port.in_id,standard_metadata.ingress_port-1);
    modify_field(standard_metadata.egress_spec, egress_spec);
}
table forward {
    reads {
		ipv4.dstAddr : exact;
    }
    actions {
        set_egr;
        _drop;
    }
}
table tiRecord{
        reads { standard_metadata.ingress_port : exact; } 
        actions { 
            aiRecordDropId_1; 
	    aiRecordDropId_2;
            aiRecordDropId_3; 
	    aiRecordDropId_4;
        } 
    }  
#define ACTION_aiRecordDropId(i) \
    action aiRecordDropId_##i() { \
        modify_field(port.in_id,standard_metadata.ingress_port-1); \
        register_read(pointer.qrearo, rrear, port.in_id);\
    	register_write(rstartId_##i, pointer.qrearo, sfNotice.startPId); \
    	register_write(rendId_##i, pointer.qrearo, sfNotice.endPId);  \
	register_write(rtype_##i, pointer.qrearo, sfNotice.type);  \
    	register_write(rrear,port.in_id, pointer.qrearo+1); \
    	modify_field(pointer.qrearo, pointer.qrearo+1); \
    }
    
#define REGISTER_rstartId(i) \
    register rstartId_##i { \
        width: 12; \
        instance_count: BUFFER_SIZE_1; \
    }
#define REGISTER_rendId(i) \
    register rendId_##i { \
        width: 12; \
        instance_count: BUFFER_SIZE_1; \
    }
#define REGISTER_type(i) \
    register rtype_##i { \
        width: 8; \
        instance_count: BUFFER_SIZE_1; \
    }


#define HANDLE_VALUE_1(i) \
    ACTION_aiRecordDropId(i) \
    REGISTER_rstartId(i) \
    REGISTER_rendId(i) \
    REGISTER_type(i) \

HANDLE_VALUE_1(1)
HANDLE_VALUE_1(2)
HANDLE_VALUE_1(3)
HANDLE_VALUE_1(4)

action aipointer() {
    register_read(pointer.qfront, rfront, port.out_id);
    register_read(pointer.qrear, rrear, port.out_id);
}
table tipointer {
    actions {aipointer;}
}

control process_1 {
    if (valid(sfNotice)){	//identify packet type
    	apply(tiRecord);  //record packet drop ID
    }
    else if(ethernet.etherType==ETHERTYPE_dot1q and ipv4.version==4){   //normal packet
        apply (forward); 
    	apply (tiDetectDrop);//detect packet drop
    }

}
  
action _drop() {
    drop();
}

register rin_cnt {
    width : 12;
    instance_count : PORT_NUM_1;
}


register rinPortPktId {
    width : 12;
    instance_count : PORT_NUM_1;
}

register rfront{   
    width : 12;
    instance_count : PORT_NUM_1;
}
register rrear{
    width : 12;
    instance_count : PORT_NUM_1;
}


register rstack{   
    width : 12;
    instance_count : BLOCK_NUM;
}

register rtop{   
    width : BLOCK_BIT;
    instance_count : 1;
}

register rSrcAddr {
    width : 32;
    instance_count : BUFFER_SIZE_1;
}
register rtDstAddr {
    width : 32;
    instance_count : BUFFER_SIZE_1;
}
register rPort {
    width :32;
    instance_count : BUFFER_SIZE_1;
}
register rProtocol {
    width :8;
    instance_count : BUFFER_SIZE_1;
}
register rvlan {
    width :12;
    instance_count : BUFFER_SIZE_1;
}
