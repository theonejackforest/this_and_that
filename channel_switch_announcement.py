import argparse
from scapy.all import sendp, RadioTap
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt

def craft_channel_switch_frame(src_mac, dst_mac, new_channel):
    dot11 = Dot11(type=0, subtype=8, addr1=dst_mac, addr2=src_mac, addr3=src_mac)
    beacon = Dot11Beacon(cap="ESS+privacy")
    essid = Dot11Elt(ID="SSID", info="TestSSID")
    dsset = Dot11Elt(ID="DSset", info=chr(new_channel))
    rsn = Dot11Elt(ID="RSNinfo", info=(
        "\x01\x00"  
        "\x00\x0f\xac\x02"  
        "\x02\x00"  
        "\x00\x0f\xac\x04"  
        "\x00\x0f\xac\x02"  
        "\x01\x00"  
        "\x00\x0f\xac\x02"  
        "\x00\x00"))  
    cs_announcement = Dot11Elt(ID="Channel Switch", info=chr(1) + chr(new_channel) + "\x00")
    frame = RadioTap()/dot11/beacon/essid/dsset/rsn/cs_announcement
    return frame

def main():
    parser = argparse.ArgumentParser(description="Craft a Wi-Fi channel switch announcement frame.")
    parser.add_argument("src_mac", help="Source MAC address")
    parser.add_argument("dst_mac", help="Destination MAC address")
    parser.add_argument("new_channel", type=int, help="New channel to switch to")
    parser.add_argument("--send", action="store_true", help="Send the packet using Scapy's sendp function")
    args = parser.parse_args()

    frame = craft_channel_switch_frame(args.src_mac, args.dst_mac, args.new_channel)
    if args.send:
        sendp(frame, iface="wlan0")  # Ensure the correct interface is specified
    else:
        frame.show()

if __name__ == "__main__":
    main()
