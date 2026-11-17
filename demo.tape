# Records docs/demo.gif. Needs vhs (brew install vhs) and Docker running.
# Usage: vhs demo.tape
Output docs/demo.gif

Set Shell "bash"
Set Theme "Catppuccin Mocha"
Set FontSize 17
Set Width 1200
Set Height 640
Set Padding 24
Set TypingSpeed 45ms
Set WindowBar Colorful
Set BorderRadius 8

# Run the lab off camera, then replay the interesting parts.
Hide
Type `PS1='\[\e[1;32m\]$ \[\e[0m\]'`
Enter
Type `say() { printf '\033[1;35m# %s\033[0m\n' "$*"; }`
Enter
Type `colorize() { sed -E $'s/request/\033[36m&\033[0m/; s/reply/\033[33m&\033[0m/'; }`
Enter
Type `chocolate-doom() { :; }`
Enter
Type "PLAY=0 ./demo.sh > /dev/null 2>&1; clear; echo lab-$((1+1))-done"
Enter
Wait+Screen@180s /lab-2-done/
Type "clear"
Enter
Show

Type "python3 -m pod.banner --pin"
Enter
Sleep 2500ms

Type "say Doom arrived over ping, 4 MB, sha256 checked by the client"
Enter
Sleep 600ms
Type "wc -c out/doom1.wad"
Enter
Sleep 2s

Type "say What it looked like on the wire: tiny requests, fat replies"
Enter
Sleep 600ms
Type "tcpdump -nn -r out/capture.pcap -c 80 2>/dev/null | tail -6 | colorize"
Enter
Sleep 4s

Type "say Now the detector reads the same capture"
Enter
Sleep 600ms
Type "python3 -m pod.detect out/capture.pcap"
Enter
Sleep 6s

Type "say And the game itself, from the file that came over ping"
Enter
Sleep 600ms
Type "chocolate-doom -iwad out/doom1.wad"
Enter
Sleep 1500ms
