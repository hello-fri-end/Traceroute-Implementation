import argparse
from scapy.all import *

def main():
    #create CLA parser
    parser= argparse.ArgumentParser()

    #add arguments

    #destination ip address
    parser.add_argument('destination', metavar= 'Destination', type= str, help='destination ip adress')

    #max_hops allowed -- optional argument
    parser.add_argument('Max_Hops', metavar='MAX_HOPS', type= int, default= 30, help='Enter the maximum allowed hops for a packet')


    #ask the user if he/she wants to perform TCP or UDP traceroute
    #optional argument
    #default - TCP traceroute
    #NOTE some firewalls may block UDP packets
    parser.add_argument('TraceRoute_Type', metavar='Traceroute_Type', choices = ['UDP', 'TCP'], type= str, default='UDP', help='Do you want to perform TCP or UDP traceroute?')

    #parse
    args= parser.parse_args()

    destination_ip= args.destination
    max_hops= args.Max_Hops
    traceroute_type= args.TraceRoute_Type

    #TTL will vary from 1 to a maximum of Max_Hops


    for i in range(1,max_hops):
        #notice the port no. is invalid-- this will be used to identify the destination
        #detination will send a destination port not found ICMP response packet
        #three probes per hop
        latency=[]
        for j in range(3):
            if traceroute_type == 'UDP': 
                packet=IP(dst= destination_ip, ttl= i)/UDP(dport=33434)
            else:
                packet=IP(dst= destination_ip, ttl= i)/TCP(dport=33434)

             #send the packets & wait for a reply

            reply=sr1(packet, verbose=0, timeout=3)

            if reply is None:
                print("***")
                break
            elif ICMP in reply and reply[ICMP].type==3: #invalid destination port ICMP reply
                latency.append(reply.time - packet.sent_time)
                if j==2:
                    print("We have reached the final destination.\n IP: {} . Latencies (1) {} ms (2) {} ms (3) {} ms".format(reply.src,latency[0]*1000, latency[1]*1000, latency[2]*1000))


                    return
            else:
                latency.append(reply.time - packet.sent_time)
                if j==2:
                    print("{} hops away: IP: {} .Latencies: (1) {} ms (2) {} ms (3) {} ms".format(i, reply.src, latency[0]*1000, latency[1]*1000, latency[2]*1000))


if __name__ == "__main__":
    main()
