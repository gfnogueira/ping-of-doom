from .banner import show
from .color import paint

show()
print("  " + paint("python3 -m pod.detect <pcap>", "green") + "   analyze a capture")
print("  " + paint("python3 -m pod.server <file>", "green") + "   serve a file over ICMP (root)")
print("  " + paint("python3 -m pod.client <host>", "green") + "   fetch it back (root)")
print("  " + paint("./demo.sh", "green") + "                      run the whole lab")
print()
