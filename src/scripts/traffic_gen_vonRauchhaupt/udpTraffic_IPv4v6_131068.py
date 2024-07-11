import argparse
from trex_stl_lib.api import *
from scapy.layers.inet6 import IPv6

# Parameters
VALID_PAYLOAD : str = 'A'
INVALID_PAYLOAD : str = 'B'
DEFAULT_VALID_PPS = 5000
DEFAULT_INVALID_PPS = 50000
SRC_IP4 = "10.3.25.49"
DEST_IP4 = "10.3.25.47"
SRC_IP6 = "2001:db8:db8::4"
DEST_IP6 = "2001:db8:db8::3"
DEST_PORT = 8080
SRC_PORT = 47777
VALID_IP_RANGE = "10.3.30.1", "10.3.30.254" #"2001:db8:abcd::1","2001:db8:abcd::fe"
INVALID_IP_RANGE = "10.4.0.1", "10.4.255.254" #"2001:0db8:0db8:0000:c0a8:0001:0000:0004","2001:0db8:0db8:0000:c0a8:fffe:0000:0004"



class STLS1(object):
    def __init__ (self):
        pass
    def create_stream1 (self,pps):
        pkt =  Ether()/IP(src=SRC_IP4,dst=DEST_IP4,id=1)/UDP(sport=SRC_PORT,dport=DEST_PORT)/(VALID_PAYLOAD.encode("ascii"))
        vm = STLScVmRaw([STLVmFlowVar("ip_src", min_value=VALID_IP_RANGE[0],max_value=VALID_IP_RANGE[1], size=4, step=1,op="inc"),
             STLVmWrFlowVar(fv_name="ip_src", pkt_offset= "IP.src"),                
             STLVmFixChecksumHw(l3_offset="IP",l4_offset="UDP",l4_type=CTRexVmInsFixHwCs.L4_TYPE_UDP)],                      
             cache_size = 254
        )
        return STLStream(packet = STLPktBuilder(pkt = pkt ,vm = vm),
               mode = STLTXCont(pps = pps),
               flow_stats = STLFlowStats(pg_id = 1))

    def create_stream2 (self,pps):
        pkt2 = Ether()/IP(src=SRC_IP4,dst=DEST_IP4,id=1)/UDP(sport=SRC_PORT,dport=DEST_PORT)/(INVALID_PAYLOAD.encode("ascii"))
        vm2 = STLScVmRaw([STLVmFlowVar("ip_src",min_value=INVALID_IP_RANGE[0],max_value=INVALID_IP_RANGE[1], size=4, step=1,op="inc"),
              STLVmWrFlowVar(fv_name="ip_src", pkt_offset= "IP.src"),
              STLVmFixChecksumHw(l3_offset="IP",l4_offset="UDP",l4_type=CTRexVmInsFixHwCs.L4_TYPE_UDP)],
              #cache_size = 65535 // does not work
            )
        return STLStream(packet = STLPktBuilder(pkt = pkt2, vm =vm2),
               mode = STLTXCont(pps = pps),
               flow_stats = STLFlowStats(pg_id = 2)) 

    def create_stream3 (self,pps):

        pkt =  Ether()/IPv6(src=SRC_IP6,dst=DEST_IP6)/UDP(sport=SRC_PORT, dport=DEST_PORT)/(VALID_PAYLOAD.encode("ascii"))
        vm = STLScVmRaw( [STLVmFlowVar ( "ip_src",  min_value=VALID_IP_RANGE[0],max_value=VALID_IP_RANGE[1], size=4, step=1,op="inc"),
                          STLVmWrFlowVar (fv_name="ip_src", pkt_offset= "IPv6.src",offset_fixup=12 ), 
                          STLVmFixChecksumHw(l3_offset="IPv6",l4_offset="UDP",l4_type=CTRexVmInsFixHwCs.L4_TYPE_UDP)],
                          cache_size = 254
        )
        return STLStream(packet = STLPktBuilder(pkt = pkt ,vm = vm),
                         mode = STLTXCont(pps = pps),
                         flow_stats = STLFlowStats(pg_id = 1))
    def create_stream4 (self,pps):
                # DNS
        pkt =  Ether()/IPv6(src=SRC_IP6,dst=DEST_IP6)/UDP(sport=SRC_PORT,dport=DEST_PORT)/(INVALID_PAYLOAD.encode("ascii"))
        vm = STLScVmRaw( [STLVmFlowVar ( "ip_src",  min_value=INVALID_IP_RANGE[0],max_value=INVALID_IP_RANGE[1], size=4, step=1,op="inc"),
                          STLVmWrFlowVar (fv_name="ip_src", pkt_offset= "IPv6.src",offset_fixup=5 ), # write ip to packet IP.sr
                          STLVmFixChecksumHw(l3_offset="IPv6",l4_offset="UDP",l4_type=CTRexVmInsFixHwCs.L4_TYPE_UDP)],
                          #cache_size = 65022
                                                 )
        return STLStream(packet = STLPktBuilder(pkt = pkt ,vm = vm),
                         mode = STLTXCont(pps = pps),
                         flow_stats = STLFlowStats(pg_id = 1))


    def get_streams (self,tunables,**kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)), 
                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument('--ppsv',type=int,default=DEFAULT_VALID_PPS,
               help="Packets per second for valid traffic")
        parser.add_argument('--ppsi',type=int,default=DEFAULT_INVALID_PPS,
               help="Packets per second for invalid traffic")
        args = parser.parse_args(tunables)
        return [self.create_stream1(args.ppsv/2),self.create_stream2(args.ppsi/2),self.create_stream3(args.ppsv/2),self.create_stream4(args.ppsi/2)]
def register():
    return STLS1()

