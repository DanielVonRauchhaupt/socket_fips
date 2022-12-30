import argparse

from trex_stl_lib.api import *

# Parameters
VALID_PAYLOAD = 100
INVALID_PAYLOAD = 250
VALID_PPS = 1
INVALID_PPS = 1
SRC_IP = "10.3.10.132"
DEST_IP = "10.3.10.131"
DEST_PORT = 8080
SRC_PORT = 47777
VALID_IP_RANGE = "10.3.11.1","10.3.11.254"
INVALID_IP_RANGE = "9.9.9.1","9.9.9.254"

class STLS1(object):
    def __init__ (self):
        pass
    def create_stream1 (self):
        pkt =  Ether()/IP(src=SRC_IP,dst=DEST_IP,id=1,tos=0)/UDP(sport=SRC_PORT,dport=DEST_PORT)/(INVALID_PAYLOAD.to_bytes(1,'big'))
        vm = STLScVmRaw([STLVmFlowVar("ip_src", min_value=VALID_IP_RANGE[0],max_value=VALID_IP_RANGE[1], size=4, step=1,op="inc"),
             STLVmWrFlowVar(fv_name="ip_src", pkt_offset= "IP.src"),                
             STLVmFixChecksumHw(l3_offset="IP",l4_offset="UDP",l4_type=CTRexVmInsFixHwCs.L4_TYPE_UDP)],                      
             cache_size = 254

        )
        return STLStream(packet = STLPktBuilder(pkt = pkt ,vm = vm),
               mode = STLTXCont(pps = VALID_PPS),
               flow_stats = STLFlowStats(pg_id = 1))
    def create_stream2 (self,pps):
        pkt2 = Ether()/IP(src=SRC_IP,dst=DEST_IP,id=1,tos=0)/UDP(sport=SRC_PORT,dport=DEST_PORT)/(INVALID_PAYLOAD.to_bytes(1,'big'))
        vm2 = STLScVmRaw([STLVmFlowVar("ip_src",min_value=INVALID_IP_RANGE[0],max_value=INVALID_IP_RANGE[1], size=4, step=1,op="inc"),
              STLVmWrFlowVar(fv_name="ip_src", pkt_offset= "IP.src"),
              STLVmFixChecksumHw(l3_offset="IP",l4_offset="UDP",l4_type=CTRexVmInsFixHwCs.L4_TYPE_UDP)],
              cache_size = 254
            )
        return STLStream(packet = STLPktBuilder(pkt = pkt2, vm =vm2),
               mode = STLTXCont(pps = INVALID_PPS),
               flow_stats = STLFlowStats(pg_id = 2))  
    def get_streams (self,tunables,**kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)), 
                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument('--pps',type=int,default=1000000,
               help="Packets per second for invalid traffic")
        args = parser.parse_args(tunables)
        return [self.create_stream1(),self.create_stream2(args.pps)]
def register():
    return STLS1()

