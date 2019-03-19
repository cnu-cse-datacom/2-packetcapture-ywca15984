import socket
import struct

def parsing_ethernet_header(data):
    ethernet_header=struct.unpack("!6c6c2s",data)
    ether_src=convert_ethernet_address(ethernet_header[0:6])    
    ether_dest=convert_ethernet_address(ethernet_header[6:12])
    ip_header="0x"+ethernet_header[12].hex()

    print("======ethernet header======")
    print("src_mac_address:", ether_src)
    print("dest_mac_address:",ether_dest)
    print("ip_version",ip_header)
def convert_ethernet_address(data):
    ethernet_addr = list()
    for i in data:
        ethernet_addr.append(i.hex())
    ethernet_addr=":".join(ethernet_addr)
    return ethernet_addr

def parsing_ip_header(data):
    ip_header=struct.unpack("!14c9c1b10c8c18c",data)
    ip_version=ip_header[14]
    ip_field="0x"+ip_header[15].hex()
    ip_total=int(ip_header[16].hex()+ip_header[17].hex(),16)
    ip_iden="0x"+ip_header[18].hex()+ip_header[19].hex()
    ip_flag="0x"+ip_header[20].hex()+ip_header[21].hex()
    ip_time=int(ip_header[22].hex(),16)
    ip_proto=ip_header[23]
    ip_check="0x"+ip_header[24].hex()+ip_header[25].hex()
    ip_src=ip_addr(ip_header[26:30])    
    ip_dest=ip_addr(ip_header[30:34])

    print("======ip header======")
    print("Version:",ip_version[0]//16)
    print("Header Length:",ip_version[0]%16*4,"bytes (",ip_version[0]%16,")")
    print("Differentiated Services Field:",ip_field) 
    print("Total Length:",ip_total)
    print("Identification:",ip_iden)
    print("Flags:",ip_flag)
    print("Time to live:",ip_time)
    if ip_proto==6:
        print("Protocol: TCP (",ip_proto,")")
    if ip_proto==17:
        print("Protocol: UDP (",ip_proto,")")
    print("Header checksum:",ip_check)
    print("Source", ip_src)
    print("Destination:",ip_dest)



    if ip_proto==6:
        parsing_tcp(data[0:60])
    if ip_proto==17:
        parsing_udp(data[0:60])



def ip_addr(data):
    ip_addr=list()
    for i in data:
        ip_addr.append(str(int(i.hex(),16)))
    ip_addr=".".join(ip_addr)
    return ip_addr

def parsing_udp(data):
    udp_header=struct.unpack("!14c9c1b10c8c18c",data)
    udp_src=int(udp_header[34].hex()+udp_header[35].hex(),16)   
    udp_dest=int(udp_header[36].hex()+udp_header[37].hex(),16)
    udp_length=int(udp_header[38].hex()+udp_header[39].hex(),16)
    udp_check="0x"+udp_header[40].hex()+udp_header[41].hex()
    
    
    print("======UDP header======")
    print("Source Port: ", udp_src)
    print("Destination Port:",udp_dest)
    print("Length: ",udp_length)
    print("Checksum:",udp_check)

def parsing_tcp(data):
    tcp_header=struct.unpack("!14c9c1b10c8c18c",data)
    tcp_src=int(tcp_header[34].hex()+tcp_header[35].hex(),16)
    tcp_dest=int(tcp_header[36].hex()+tcp_header[37].hex(),16)
    tcp_seqnum=int(tcp_header[38].hex()+tcp_header[39].hex()+tcp_header[40].hex()+tcp_header[41].hex(),16)
    tcp_acknow=int(tcp_header[42].hex()+tcp_header[43].hex()+tcp_header[44].hex()+tcp_header[45].hex(),16)
    tcp_hl=int(tcp_header[46].hex(),16)
    tcp_flag=str(hex(int(tcp_header[46].hex()+tcp_header[47].hex(),16)%(16*16*16)))
    
    tcp_win=int(tcp_header[48].hex()+tcp_header[49].hex(),16)
    tcp_check="0x"+tcp_header[50].hex()+tcp_header[51].hex()
    tcp_pointer=int(tcp_header[52].hex()+tcp_header[53].hex(),16)


    print("======TCP header======")
    print("Source Port: ", tcp_src)
    print("Destination Port:",tcp_dest)
    print("Sequence number:",tcp_seqnum)
    print("Acknowledgment number:",tcp_acknow)
    print("Header Length:",tcp_hl//16*4,"bytes(",tcp_hl//16,")")
    print("Flags:",tcp_flag)
    print("Windowvsize value:: ",tcp_win)
    print("Checksum:",tcp_check)
    print("Urgent pointer:",tcp_pointer)




recv_socket=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(0x800))

while True:
    data=recv_socket.recvfrom(20000)
    parsing_ethernet_header(data[0][0:14])
    parsing_ip_header(data[0][0:60])
