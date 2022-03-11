#!/usr/bin/env python

from scapy.all import *


class OutHeader(Packet):
    name = "OutHeader"
    fields_desc = [ShortField("qid", 0), IntField("dstip", 0), ShortField("index", 0)]
    
    def extract_padding(self, p):
         return p, ""

    def guess_payload_class(self, payload):
        return Ether


def handle_pkt(pkt):
    global OUT_DATA
    parsed_pkt = OutHeader(_pkt=bytes(pkt))
    parsed_pkt.show2()
    
    data = '{},{},{}'.format(parsed_pkt[OutHeader].qid, parsed_pkt[OutHeader].dstip, parsed_pkt[OutHeader].index)
    OUT_DATA.append(data)
    
    sys.stdout.flush()
    return


def main():
    # TODO: Modify prn argument in sniff function
    sniff(iface="eth0", prn=lambda x: handle_pkt(x), timeout=90)
    
    if len(OUT_DATA) >= 1:
        working_dir = '/home/vagrant/cs176b-tutorials/tutorial5'
        with open('{}/switch_stats.csv'.format(working_dir), 'w') as fp:
            fp.write('\n'.join(OUT_DATA)+'\n')

    return



if __name__ == '__main__':
    OUT_DATA = ["qid,dstip,index"]
    main()
