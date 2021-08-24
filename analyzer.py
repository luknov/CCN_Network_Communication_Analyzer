from scapy.all import *
from collections import Counter

# Otvorenie .pcap súboru
def otvor_pcap_subor(subor):
    pakety = rdpcap("vzorky_pcap_na_analyzu/" + subor)
    packet_list = PacketList([p for p in pakety])
    return packet_list

# Zistenie dĺžky rámca prenašaného po médiu
def dlzka_ramca_po_mediu(dlzka_ramca):
    if dlzka_ramca >= 60:
        return dlzka_ramca + 4
    else:
        return 64

# Zistenie cieľovej IP adresy
def cielova_IP_f(upraveny_ramec):
    dst_IP_int = []
    for x in range(4):
        dst_IP_int.append(str(int(upraveny_ramec[30 + x], 16)))
    dst_IP = ".".join(dst_IP_int)
    return dst_IP

# Zistenie zdrojovej IP adresy
def zdrojova_IP_f(upraveny_ramec):
    src_IP_int = []
    for x in range(4):
        src_IP_int.append(str(int(upraveny_ramec[26 + x], 16)))
    src_IP = ".".join(src_IP_int)
    return src_IP

# Filter pre nájdenie protokolu z externého súboru
def filter(subor, bajty):
    protokol = "Neznámy protokol"
    for line in subor:
        line = line.split(" ")
        if line[0] == bajty:
            protokol = line[1].strip()
            break
    return protokol

# Funkcia pre nájdenie IP adries a vnoreného IP protokolu
def IP_f(vnoreny_p, file_out, upraveny_ramec, prijimajuce_list):
    src_IP = zdrojova_IP_f(upraveny_ramec)
    dst_IP = cielova_IP_f(upraveny_ramec)

    if vnoreny_p == "IPv4":
        prijimajuce_list.append(dst_IP)

    file_out.write("Zdrojová IP adresa: " + src_IP + "\n")
    file_out.write("Cieľová IP adresa: " + dst_IP + "\n")


# Výpis rámca po 16 B
def vypis_ramca(dlzka_ramca, file_out, upraveny_ramec):
    pom = dlzka_ramca % 16
    pom2 = dlzka_ramca // 16
    for i in range(0, pom2):
        file_out.write(" ".join(upraveny_ramec[i * 16:16 * (i + 1)]) + "\n")
    file_out.write(" ".join(upraveny_ramec[pom2 * 16:pom2 * 16 + pom]) + "\n" + "\n")

# Zistenie všetkých prijímacích uzlov IP + načastejší s počtom paketov
def zisti_IP_uzly(dst_IP_list, file_out):
    file_out.write("IP adresy prijímajúcich uzlov: \n")
    for item in dst_IP_list:
        file_out.write(item + "\n")
    pocet_IP = Counter(dst_IP_list)
    najcastejsia_IP = pocet_IP.most_common(1)[0][0]
    pocet_paketov_IP = str(pocet_IP.most_common(1)[0][1])
    file_out.write("\nAdresa uzla s najväčším počtom prijatých paketov: \n" + najcastejsia_IP + " - " + pocet_paketov_IP + " paketov")

# Čítanie všetkých rámcov súboru
def vsetky_ramce_f(packetlist, file_out):
    prijimajuce_IP = []
    poradie = 1
    for pkt in packetlist:
        b = raw(pkt)
        # Upravenie rámca
        ramec = b.hex(" ").upper()
        ramec_split = ramec.split(" ")

        file_out.write("rámec " + str(poradie) + "\n")

        # Dĺžka rámca
        dlzka_ramca = len(pkt)
        file_out.write("dĺžka rámca poskytnutá pcap api: " + str(dlzka_ramca) + "\n")
        dlzka_ramca_m = dlzka_ramca_po_mediu(dlzka_ramca)
        file_out.write("dĺžka rámca prenášaneho po mediu: " + str(dlzka_ramca_m) + "\n")

        # Upravenie bytov pre zistenie, či ide o Ethernet II alebo IEEE 802.3
        pole_3 = "".join(ramec_split[12:14])
        pole_3_int = int(pole_3, 16)
        vnoreny_protokol = []
        if pole_3_int >= 1600:
            file_out.write("Ethernet II\n")
            f_E = open("EtherTypes.txt", "r")
            vnoreny_protokol = filter(f_E, pole_3)
            f_E.close()
            file_out.write(vnoreny_protokol + "\n")

        else:
            pole_4 = "".join(ramec_split[14:15])
            if pole_4 == "FF":
                file_out.write("IEEE 802.3 - RAW\n")
                vnoreny_protokol = "IPX"
                file_out.write(vnoreny_protokol + "\n")
            elif pole_4 == "AA":
                file_out.write("IEEE 802.3 - LLC + SNAP\n")
            else:
                file_out.write("IEEE 802.3 - LLC\n")
                pole_4 = ramec_split[14]
                f_LSAP = open("LSAPs.txt", "r")
                vnoreny_protokol = filter(f_LSAP, pole_4)
                f_LSAP.close()
                file_out.write(vnoreny_protokol + "\n")

        # MAC adresy
        dst_mac = ":".join(ramec_split[:6])
        src_mac = ":".join(ramec_split[6:12])
        file_out.write("Zdrojová MAC adresa: " + src_mac + "\n")
        file_out.write("Cieľová MAC adresa: " + dst_mac + "\n")

        # Ak je typ Ethernet II IP - zistím a vypíšem adresy + IP protokol
        ip_protokol = ""
        if vnoreny_protokol == "IPv4" or vnoreny_protokol == "IPv6":
            IP_f(vnoreny_protokol, file_out, ramec_split, prijimajuce_IP)
            f_IP = open("IPProtocolNumbers.txt", "r")
            ip_protokol = filter(f_IP, ramec_split[23])
            f_IP.close()
            file_out.write(ip_protokol + "\n")

        if ip_protokol == "TCP":
            src_port = "".join(ramec_split[34:36])
            src_port_dec = str(int(src_port, 16))
            dst_port = "".join(ramec_split[36:38])
            dst_port_dec = str(int(dst_port, 16))
            f_tcp = open("TCPports.txt", "r")
            tcp_port = ""
            for line in f_tcp:
                line = line.split(" ")
                if line[0] == dst_port_dec or line[0] == src_port_dec:
                    tcp_port = line[1].strip()
                    break
            f_tcp.close()
            file_out.write(tcp_port + "\n" + "zdrojový port: " + src_port_dec + "\n" + "cieľový port: " + dst_port_dec + "\n")

        elif ip_protokol == "UDP":
            src_port = "".join(ramec_split[34:36])
            src_port_dec = str(int(src_port, 16))
            dst_port = "".join(ramec_split[36:38])
            dst_port_dec = str(int(dst_port, 16))
            f_tcp = open("UDPports.txt", "r")
            udp_port = ""
            for line in f_tcp:
                line = line.split(" ")
                if line[0] == dst_port_dec or line[0] == src_port_dec:
                    udp_port = line[1].strip()
                    break
            f_tcp.close()
            file_out.write(udp_port + "\n" + "zdrojový port: " + src_port_dec + "\n" + "cieľový port: " + dst_port_dec + "\n")
        # Výpis rámca
        vypis_ramca(dlzka_ramca, file_out, ramec_split)

        poradie = poradie + 1

    # Na konci výpis všetkých prijímajúcich IP uzlov
    zisti_IP_uzly(prijimajuce_IP, file_out)

# Funkcia pre zistenie HTTP komunikácie
def HTTP_f(packetlist, file_out):
    poradie = 1
    ramce_http = []
    cisla_ramcov = []
    for pkt in packetlist:
        b = raw(pkt)
        # Upravenie rámca
        ramec = b.hex(" ").upper()
        ramec_split = ramec.split(" ")

        pole_3 = "".join(ramec_split[12:14])
        pole_3_int = int(pole_3, 16)
        if pole_3_int >= 1600:
            f_E = open("EtherTypes.txt", "r")
            vnoreny_p = filter(f_E, pole_3)
            f_E.close()

            if vnoreny_p == "IPv4":
                f_IP = open("IPProtocolNumbers.txt", "r")
                ip_protokol = filter(f_IP, ramec_split[23])
                f_IP.close()

                if ip_protokol == "TCP":
                    src_port = "".join(ramec_split[34:36])
                    src_port_dec = str(int(src_port, 16))
                    dst_port = "".join(ramec_split[36:38])
                    dst_port_dec = str(int(dst_port, 16))
                    f_tcp = open("TCPports.txt", "r")
                    tcp_port = ""
                    for line in f_tcp:
                        line = line.split(" ")
                        if line[0] == dst_port_dec or line[0] == src_port_dec:
                            tcp_port = line[1].strip()
                            break
                    f_tcp.close()

                    # Uloženie HTTP rámcov
                    if tcp_port == "HTTP":
                        ramce_http.append(pkt)
                        cisla_ramcov.append(poradie)

        poradie = poradie + 1

    b = raw(ramce_http[0])
    ramec_http = b.hex(" ").upper()
    ramec_http_split = ramec_http.split(" ")

    src_port = "".join(ramec_http_split[34:36])
    src_ports = []
    src_ports.append(str(int(src_port, 16)))

    dst_ports = []
    dst_port = "".join(ramec_http_split[36:38])
    dst_ports.append(str(int(dst_port, 16)))

    komunikacia1 = []
    komunikacia1.append(ramce_http[0])
    cisla_ramcov_komunikacie = []
    cisla_ramcov_komunikacie.append(cisla_ramcov[0])
    for i in range(1, len(ramce_http)):
        b = raw(ramce_http[i])
        # Upravenie rámca
        ramec = b.hex(" ").upper()
        ramec_split = ramec.split(" ")

        src_port = "".join(ramec_split[34:36])
        src_port_int = str(int(src_port, 16))
        dst_port = "".join(ramec_split[36:38])
        dst_port_int = str(int(dst_port, 16))

        # Kontrolovanie komunikácie podľa portov
        if (src_port_int == dst_ports[0] and dst_port_int == src_ports[0]) or (src_port_int == src_ports[0] and dst_port_int == dst_ports[0]):
            komunikacia1.append(ramce_http[i])
            cisla_ramcov_komunikacie.append(cisla_ramcov[i])

    # TCP flagy
    syn = 0
    fin = 0
    rst = 0
    for pkt in komunikacia1:
        b = raw(pkt)
        # Upravenie rámca
        ramec = b.hex(" ").upper()
        ramec_split = ramec.split(" ")

        flags_hex = ramec_split[47]
        flags = "{0:08b}".format(int(flags_hex, 16))

        # Zistenie flagov
        if flags[6] == "1":
            syn = 1
        elif flags[7] == "1" and syn == 1:
            fin = fin + 1
        elif flags[5] == "1":
            rst = 1

    # Či ide o úplnú alebo neúplnú komunikáciu
    if syn == 1 and (fin == 2 or rst == 1):
        file_out.write("Úplná komunikácia\n")
        i = 0
        for pkt in komunikacia1:
            b = raw(pkt)
            # Upravenie rámca
            ramec = b.hex(" ").upper()
            ramec_split = ramec.split(" ")
            dlzka_ramca = len(pkt)
            dlzka_ramca_m = dlzka_ramca_po_mediu(dlzka_ramca)
            dst_mac = ":".join(ramec_split[:6])
            src_mac = ":".join(ramec_split[6:12])
            src_port = "".join(ramec_split[34:36])
            src_port_int = str(int(src_port, 16))
            dst_port = "".join(ramec_split[36:38])
            dst_port_int = str(int(dst_port, 16))
            src_IP = zdrojova_IP_f(ramec_split)
            dst_IP = cielova_IP_f(ramec_split)
            file_out.write("rámec " + str(cisla_ramcov_komunikacie[i]) + "\ndĺžka rámca poskytnutá pcap api: " + str(
                dlzka_ramca) + "\ndĺžka rámca prenášaného po médiu: " +
                           str(
                               dlzka_ramca_m) + "\n" + "Ethernet II\nZdrojová MAC adresa: " + src_mac + "\nCieľová MAC adresa: "
                           + dst_mac + "\n" + "IPv4\nZdrojová IP: " + src_IP + "\nCieľová IP: " + dst_IP + "\nTCP\n" + "HTTP\nZdrojový port: " + src_port_int + "\nCieľový port: " + dst_port_int + "\n")
            vypis_ramca(dlzka_ramca, file_out, ramec_split)
            i = i + 1
    else:
        file_out.write("Neúplná komunikácia\n")
        i = 0
        for pkt in komunikacia1:
            b = raw(pkt)
            # Upravenie rámca
            ramec = b.hex(" ").upper()
            ramec_split = ramec.split(" ")
            dlzka_ramca = len(pkt)
            dlzka_ramca_m = dlzka_ramca_po_mediu(dlzka_ramca)
            dst_mac = ":".join(ramec_split[:6])
            src_mac = ":".join(ramec_split[6:12])
            src_port = "".join(ramec_split[34:36])
            src_port_int = str(int(src_port, 16))
            dst_port = "".join(ramec_split[36:38])
            dst_port_int = str(int(dst_port, 16))
            src_IP = zdrojova_IP_f(ramec_split)
            dst_IP = cielova_IP_f(ramec_split)
            file_out.write("rámec " + str(cisla_ramcov_komunikacie[i]) + "\ndĺžka rámca poskytnutá pcap api: " + str(dlzka_ramca) + "\ndĺžka rámca prenášaného po médiu: " +
                           str(dlzka_ramca_m) + "\n" + "Ethernet II\nZdrojová MAC adresa: " + src_mac + "\nCieľová MAC adresa: "
                           + dst_mac + "\n" + "IPv4\nZdrojová IP: " + src_IP + "\nCieľová IP: " + dst_IP + "\nTCP\n" + "HTTP\nZdrojový port: " + src_port_int + "\nCieľový port: " + dst_port_int + "\n")
            vypis_ramca(dlzka_ramca, file_out, ramec_split)
            i = i + 1

def HTTPS_f(packetlist, file_out):
    poradie = 1
    ramce_https = []
    cisla_ramcov = []
    for pkt in packetlist:
        b = raw(pkt)
        # Upravenie rámca
        ramec = b.hex(" ").upper()
        ramec_split = ramec.split(" ")

        pole_3 = "".join(ramec_split[12:14])
        pole_3_int = int(pole_3, 16)
        if pole_3_int >= 1600:
            f_E = open("EtherTypes.txt", "r")
            vnoreny_p = filter(f_E, pole_3)
            f_E.close()

            if vnoreny_p == "IPv4":
                f_IP = open("IPProtocolNumbers.txt", "r")
                ip_protokol = filter(f_IP, ramec_split[23])
                f_IP.close()

                if ip_protokol == "TCP":
                    src_port = "".join(ramec_split[34:36])
                    src_port_dec = str(int(src_port, 16))
                    dst_port = "".join(ramec_split[36:38])
                    dst_port_dec = str(int(dst_port, 16))
                    f_tcp = open("TCPports.txt", "r")
                    tcp_port = ""
                    for line in f_tcp:
                        line = line.split(" ")
                        if line[0] == dst_port_dec or line[0] == src_port_dec:
                            tcp_port = line[1].strip()
                            break
                    f_tcp.close()

                    if tcp_port == "HTTPS":
                        ramce_https.append(pkt)
                        cisla_ramcov.append(poradie)

        poradie = poradie + 1

    b = raw(ramce_https[0])
    ramec_https = b.hex(" ").upper()
    ramec_https_split = ramec_https.split(" ")

    src_port = "".join(ramec_https_split[34:36])
    src_ports = []
    src_ports.append(str(int(src_port, 16)))

    dst_ports = []
    dst_port = "".join(ramec_https_split[36:38])
    dst_ports.append(str(int(dst_port, 16)))

    komunikacia1 = []
    komunikacia1.append(ramce_https[0])
    cisla_ramcov_komunikacie = []
    cisla_ramcov_komunikacie.append(cisla_ramcov[0])
    for i in range(1, len(ramce_https)):
        b = raw(ramce_https[i])
        # Upravenie rámca
        ramec = b.hex(" ").upper()
        ramec_split = ramec.split(" ")

        src_port = "".join(ramec_split[34:36])
        src_port_int = str(int(src_port, 16))
        dst_port = "".join(ramec_split[36:38])
        dst_port_int = str(int(dst_port, 16))

        if (src_port_int == dst_ports[0] and dst_port_int == src_ports[0]) or (src_port_int == src_ports[0] and dst_port_int == dst_ports[0]):
            komunikacia1.append(ramce_https[i])
            cisla_ramcov_komunikacie.append(cisla_ramcov[i])

    syn = 0
    fin = 0
    rst = 0
    for pkt in komunikacia1:
        b = raw(pkt)
        # Upravenie rámca
        ramec = b.hex(" ").upper()
        ramec_split = ramec.split(" ")

        flags_hex = ramec_split[47]
        flags = "{0:08b}".format(int(flags_hex, 16))

        if flags[6] == "1":
            syn = 1
        elif flags[7] == "1" and syn == 1:
            fin = fin + 1
        elif flags[5] == "1":
            rst = 1

    if syn == 1 and (fin == 2 or rst == 1):
        file_out.write("Úplná komunikácia\n")
        i = 0
        for pkt in komunikacia1:
            b = raw(pkt)
            # Upravenie rámca
            ramec = b.hex(" ").upper()
            ramec_split = ramec.split(" ")
            dlzka_ramca = len(pkt)
            dlzka_ramca_m = dlzka_ramca_po_mediu(dlzka_ramca)
            dst_mac = ":".join(ramec_split[:6])
            src_mac = ":".join(ramec_split[6:12])
            src_port = "".join(ramec_split[34:36])
            src_port_int = str(int(src_port, 16))
            dst_port = "".join(ramec_split[36:38])
            dst_port_int = str(int(dst_port, 16))
            src_IP = zdrojova_IP_f(ramec_split)
            dst_IP = cielova_IP_f(ramec_split)
            file_out.write("rámec " + str(cisla_ramcov_komunikacie[i]) + "\ndĺžka rámca poskytnutá pcap api: " + str(
                dlzka_ramca) + "\ndĺžka rámca prenášaného po médiu: " +
                           str(
                               dlzka_ramca_m) + "\n" + "Ethernet II\nZdrojová MAC adresa: " + src_mac + "\nCieľová MAC adresa: "
                           + dst_mac + "\n" + "IPv4\nZdrojová IP: " + src_IP + "\nCieľová IP: " + dst_IP + "\nTCP\n" + "HTTPS\nZdrojový port: " + src_port_int + "\nCieľový port: " + dst_port_int + "\n")
            vypis_ramca(dlzka_ramca, file_out, ramec_split)
            i = i + 1
    else:
        file_out.write("Neúplná komunikácia\n")
        i = 0
        for pkt in komunikacia1:
            b = raw(pkt)
            # Upravenie rámca
            ramec = b.hex(" ").upper()
            ramec_split = ramec.split(" ")
            dlzka_ramca = len(pkt)
            dlzka_ramca_m = dlzka_ramca_po_mediu(dlzka_ramca)
            dst_mac = ":".join(ramec_split[:6])
            src_mac = ":".join(ramec_split[6:12])
            src_port = "".join(ramec_split[34:36])
            src_port_int = str(int(src_port, 16))
            dst_port = "".join(ramec_split[36:38])
            dst_port_int = str(int(dst_port, 16))
            src_IP = zdrojova_IP_f(ramec_split)
            dst_IP = cielova_IP_f(ramec_split)
            file_out.write("rámec " + str(cisla_ramcov_komunikacie[i]) + "\ndĺžka rámca poskytnutá pcap api: " + str(dlzka_ramca) + "\ndĺžka rámca prenášaného po médiu: " +
                           str(dlzka_ramca_m) + "\n" + "Ethernet II\nZdrojová MAC adresa: " + src_mac + "\nCieľová MAC adresa: "
                           + dst_mac + "\n" + "IPv4\nZdrojová IP: " + src_IP + "\nCieľová IP: " + dst_IP + "\nTCP\n" + "HTTPS\nZdrojový port: " + src_port_int + "\nCieľový port: " + dst_port_int + "\n")
            vypis_ramca(dlzka_ramca, file_out, ramec_split)
            i = i + 1

def TELNET_f(packetlist, file_out):
    poradie = 1
    ramce_telnet = []
    cisla_ramcov = []
    for pkt in packetlist:
        b = raw(pkt)
        # Upravenie rámca
        ramec = b.hex(" ").upper()
        ramec_split = ramec.split(" ")

        pole_3 = "".join(ramec_split[12:14])
        pole_3_int = int(pole_3, 16)
        if pole_3_int >= 1600:
            f_E = open("EtherTypes.txt", "r")
            vnoreny_p = filter(f_E, pole_3)
            f_E.close()

            if vnoreny_p == "IPv4":
                f_IP = open("IPProtocolNumbers.txt", "r")
                ip_protokol = filter(f_IP, ramec_split[23])
                f_IP.close()

                if ip_protokol == "TCP":
                    src_port = "".join(ramec_split[34:36])
                    src_port_dec = str(int(src_port, 16))
                    dst_port = "".join(ramec_split[36:38])
                    dst_port_dec = str(int(dst_port, 16))
                    f_tcp = open("TCPports.txt", "r")
                    tcp_port = ""
                    for line in f_tcp:
                        line = line.split(" ")
                        if line[0] == dst_port_dec or line[0] == src_port_dec:
                            tcp_port = line[1].strip()
                            break
                    f_tcp.close()

                    if tcp_port == "TELNET":
                        ramce_telnet.append(pkt)
                        cisla_ramcov.append(poradie)

        poradie = poradie + 1

    b = raw(ramce_telnet[0])
    ramec_telnet = b.hex(" ").upper()
    ramec_telnet_split = ramec_telnet.split(" ")

    src_port = "".join(ramec_telnet_split[34:36])
    src_ports = []
    src_ports.append(str(int(src_port, 16)))

    dst_ports = []
    dst_port = "".join(ramec_telnet_split[36:38])
    dst_ports.append(str(int(dst_port, 16)))

    komunikacia1 = []
    komunikacia1.append(ramce_telnet[0])
    cisla_ramcov_komunikacie = []
    cisla_ramcov_komunikacie.append(cisla_ramcov[0])
    for i in range(1, len(ramce_telnet)):
        b = raw(ramce_telnet[i])
        # Upravenie rámca
        ramec = b.hex(" ").upper()
        ramec_split = ramec.split(" ")

        src_port = "".join(ramec_split[34:36])
        src_port_int = str(int(src_port, 16))
        dst_port = "".join(ramec_split[36:38])
        dst_port_int = str(int(dst_port, 16))

        if (src_port_int == dst_ports[0] and dst_port_int == src_ports[0]) or (src_port_int == src_ports[0] and dst_port_int == dst_ports[0]):
            komunikacia1.append(ramce_telnet[i])
            cisla_ramcov_komunikacie.append(cisla_ramcov[i])

    syn = 0
    fin = 0
    rst = 0
    for pkt in komunikacia1:
        b = raw(pkt)
        # Upravenie rámca
        ramec = b.hex(" ").upper()
        ramec_split = ramec.split(" ")

        flags_hex = ramec_split[47]
        flags = "{0:08b}".format(int(flags_hex, 16))

        if flags[6] == "1":
            syn = 1
        elif flags[7] == "1" and syn == 1:
            fin = fin + 1
        elif flags[5] == "1":
            rst = 1

    if syn == 1 and (fin == 2 or rst == 1):
        file_out.write("Úplná komunikácia\n")
        i = 0
        for pkt in komunikacia1:
            b = raw(pkt)
            # Upravenie rámca
            ramec = b.hex(" ").upper()
            ramec_split = ramec.split(" ")
            dlzka_ramca = len(pkt)
            dlzka_ramca_m = dlzka_ramca_po_mediu(dlzka_ramca)
            dst_mac = ":".join(ramec_split[:6])
            src_mac = ":".join(ramec_split[6:12])
            src_port = "".join(ramec_split[34:36])
            src_port_int = str(int(src_port, 16))
            dst_port = "".join(ramec_split[36:38])
            dst_port_int = str(int(dst_port, 16))
            src_IP = zdrojova_IP_f(ramec_split)
            dst_IP = cielova_IP_f(ramec_split)
            file_out.write("rámec " + str(cisla_ramcov_komunikacie[i]) + "\ndĺžka rámca poskytnutá pcap api: " + str(
                dlzka_ramca) + "\ndĺžka rámca prenášaného po médiu: " +
                           str(
                               dlzka_ramca_m) + "\n" + "Ethernet II\nZdrojová MAC adresa: " + src_mac + "\nCieľová MAC adresa: "
                           + dst_mac + "\n" + "IPv4\nZdrojová IP: " + src_IP + "\nCieľová IP: " + dst_IP + "\nTCP\n" + "TELNET\nZdrojový port: " + src_port_int + "\nCieľový port: " + dst_port_int + "\n")
            vypis_ramca(dlzka_ramca, file_out, ramec_split)
            i = i + 1
    else:
        file_out.write("Neúplná komunikácia\n")
        i = 0
        for pkt in komunikacia1:
            b = raw(pkt)
            # Upravenie rámca
            ramec = b.hex(" ").upper()
            ramec_split = ramec.split(" ")
            dlzka_ramca = len(pkt)
            dlzka_ramca_m = dlzka_ramca_po_mediu(dlzka_ramca)
            dst_mac = ":".join(ramec_split[:6])
            src_mac = ":".join(ramec_split[6:12])
            src_port = "".join(ramec_split[34:36])
            src_port_int = str(int(src_port, 16))
            dst_port = "".join(ramec_split[36:38])
            dst_port_int = str(int(dst_port, 16))
            src_IP = zdrojova_IP_f(ramec_split)
            dst_IP = cielova_IP_f(ramec_split)
            file_out.write("rámec " + str(cisla_ramcov_komunikacie[i]) + "\ndĺžka rámca poskytnutá pcap api: " + str(dlzka_ramca) + "\ndĺžka rámca prenášaného po médiu: " +
                           str(dlzka_ramca_m) + "\n" + "Ethernet II\nZdrojová MAC adresa: " + src_mac + "\nCieľová MAC adresa: "
                           + dst_mac + "\n" + "IPv4\nZdrojová IP: " + src_IP + "\nCieľová IP: " + dst_IP + "\nTCP\n" + "TELNET\nZdrojový port: " + src_port_int + "\nCieľový port: " + dst_port_int + "\n")
            vypis_ramca(dlzka_ramca, file_out, ramec_split)
            i = i + 1

def FTP_C_f(packetlist, file_out):
    poradie = 1
    ramce_ftp_c = []
    cisla_ramcov = []
    for pkt in packetlist:
        b = raw(pkt)
        # Upravenie rámca
        ramec = b.hex(" ").upper()
        ramec_split = ramec.split(" ")

        pole_3 = "".join(ramec_split[12:14])
        pole_3_int = int(pole_3, 16)
        if pole_3_int >= 1600:
            f_E = open("EtherTypes.txt", "r")
            vnoreny_p = filter(f_E, pole_3)
            f_E.close()

            if vnoreny_p == "IPv4":
                f_IP = open("IPProtocolNumbers.txt", "r")
                ip_protokol = filter(f_IP, ramec_split[23])
                f_IP.close()

                if ip_protokol == "TCP":
                    src_port = "".join(ramec_split[34:36])
                    src_port_dec = str(int(src_port, 16))
                    dst_port = "".join(ramec_split[36:38])
                    dst_port_dec = str(int(dst_port, 16))
                    f_tcp = open("TCPports.txt", "r")
                    tcp_port = ""
                    for line in f_tcp:
                        line = line.split(" ")
                        if line[0] == dst_port_dec or line[0] == src_port_dec:
                            tcp_port = line[1].strip()
                            break
                    f_tcp.close()

                    if tcp_port == "FTP-CONTROL":
                        ramce_ftp_c.append(pkt)
                        cisla_ramcov.append(poradie)

        poradie = poradie + 1

    b = raw(ramce_ftp_c[0])
    ramec_ftp_c = b.hex(" ").upper()
    ramec_ftp_c_split = ramec_ftp_c.split(" ")

    src_port = "".join(ramec_ftp_c_split[34:36])
    src_ports = []
    src_ports.append(str(int(src_port, 16)))

    dst_ports = []
    dst_port = "".join(ramec_ftp_c_split[36:38])
    dst_ports.append(str(int(dst_port, 16)))

    komunikacia1 = []
    komunikacia1.append(ramce_ftp_c[0])
    cisla_ramcov_komunikacie = []
    cisla_ramcov_komunikacie.append(cisla_ramcov[0])
    for i in range(1, len(ramce_ftp_c)):
        b = raw(ramce_ftp_c[i])
        # Upravenie rámca
        ramec = b.hex(" ").upper()
        ramec_split = ramec.split(" ")

        src_port = "".join(ramec_split[34:36])
        src_port_int = str(int(src_port, 16))
        dst_port = "".join(ramec_split[36:38])
        dst_port_int = str(int(dst_port, 16))

        if (src_port_int == dst_ports[0] and dst_port_int == src_ports[0]) or (src_port_int == src_ports[0] and dst_port_int == dst_ports[0]):
            komunikacia1.append(ramce_ftp_c[i])
            cisla_ramcov_komunikacie.append(cisla_ramcov[i])

    syn = 0
    fin = 0
    rst = 0
    for pkt in komunikacia1:
        b = raw(pkt)
        # Upravenie rámca
        ramec = b.hex(" ").upper()
        ramec_split = ramec.split(" ")

        flags_hex = ramec_split[47]
        flags = "{0:08b}".format(int(flags_hex, 16))

        if flags[6] == "1":
            syn = 1
        elif flags[7] == "1" and syn == 1:
            fin = fin + 1
        elif flags[5] == "1":
            rst = 1

    if syn == 1 and (fin == 2 or rst == 1):
        file_out.write("Úplná komunikácia\n")
        i = 0
        for pkt in komunikacia1:
            b = raw(pkt)
            # Upravenie rámca
            ramec = b.hex(" ").upper()
            ramec_split = ramec.split(" ")
            dlzka_ramca = len(pkt)
            dlzka_ramca_m = dlzka_ramca_po_mediu(dlzka_ramca)
            dst_mac = ":".join(ramec_split[:6])
            src_mac = ":".join(ramec_split[6:12])
            src_port = "".join(ramec_split[34:36])
            src_port_int = str(int(src_port, 16))
            dst_port = "".join(ramec_split[36:38])
            dst_port_int = str(int(dst_port, 16))
            src_IP = zdrojova_IP_f(ramec_split)
            dst_IP = cielova_IP_f(ramec_split)
            file_out.write("rámec " + str(cisla_ramcov_komunikacie[i]) + "\ndĺžka rámca poskytnutá pcap api: " + str(
                dlzka_ramca) + "\ndĺžka rámca prenášaného po médiu: " +
                           str(
                               dlzka_ramca_m) + "\n" + "Ethernet II\nZdrojová MAC adresa: " + src_mac + "\nCieľová MAC adresa: "
                           + dst_mac + "\n" + "IPv4\nZdrojová IP: " + src_IP + "\nCieľová IP: " + dst_IP + "\nTCP\n" + "FTP-CONTROL\nZdrojový port: " + src_port_int + "\nCieľový port: " + dst_port_int + "\n")
            vypis_ramca(dlzka_ramca, file_out, ramec_split)
            i = i + 1
    else:
        file_out.write("Neúplná komunikácia\n")
        i = 0
        for pkt in komunikacia1:
            b = raw(pkt)
            # Upravenie rámca
            ramec = b.hex(" ").upper()
            ramec_split = ramec.split(" ")
            dlzka_ramca = len(pkt)
            dlzka_ramca_m = dlzka_ramca_po_mediu(dlzka_ramca)
            dst_mac = ":".join(ramec_split[:6])
            src_mac = ":".join(ramec_split[6:12])
            src_port = "".join(ramec_split[34:36])
            src_port_int = str(int(src_port, 16))
            dst_port = "".join(ramec_split[36:38])
            dst_port_int = str(int(dst_port, 16))
            src_IP = zdrojova_IP_f(ramec_split)
            dst_IP = cielova_IP_f(ramec_split)
            file_out.write("rámec " + str(cisla_ramcov_komunikacie[i]) + "\ndĺžka rámca poskytnutá pcap api: " + str(dlzka_ramca) + "\ndĺžka rámca prenášaného po médiu: " +
                           str(dlzka_ramca_m) + "\n" + "Ethernet II\nZdrojová MAC adresa: " + src_mac + "\nCieľová MAC adresa: "
                           + dst_mac + "\n" + "IPv4\nZdrojová IP: " + src_IP + "\nCieľová IP: " + dst_IP + "\nTCP\n" + "FTP-CONTROL\nZdrojový port: " + src_port_int + "\nCieľový port: " + dst_port_int + "\n")
            vypis_ramca(dlzka_ramca, file_out, ramec_split)
            i = i + 1

def FTP_D_f(packetlist, file_out):
    poradie = 1
    ramce_ftp_d = []
    cisla_ramcov = []
    for pkt in packetlist:
        b = raw(pkt)
        # Upravenie rámca
        ramec = b.hex(" ").upper()
        ramec_split = ramec.split(" ")

        pole_3 = "".join(ramec_split[12:14])
        pole_3_int = int(pole_3, 16)
        if pole_3_int >= 1600:
            f_E = open("EtherTypes.txt", "r")
            vnoreny_p = filter(f_E, pole_3)
            f_E.close()

            if vnoreny_p == "IPv4":
                f_IP = open("IPProtocolNumbers.txt", "r")
                ip_protokol = filter(f_IP, ramec_split[23])
                f_IP.close()

                if ip_protokol == "TCP":
                    src_port = "".join(ramec_split[34:36])
                    src_port_dec = str(int(src_port, 16))
                    dst_port = "".join(ramec_split[36:38])
                    dst_port_dec = str(int(dst_port, 16))
                    f_tcp = open("TCPports.txt", "r")
                    tcp_port = ""
                    for line in f_tcp:
                        line = line.split(" ")
                        if line[0] == dst_port_dec or line[0] == src_port_dec:
                            tcp_port = line[1].strip()
                            break
                    f_tcp.close()

                    if tcp_port == "FTP-DATA":
                        ramce_ftp_d.append(pkt)
                        cisla_ramcov.append(poradie)

        poradie = poradie + 1

    b = raw(ramce_ftp_d[0])
    ramec_ftp_d = b.hex(" ").upper()
    ramec_ftp_d_split = ramec_ftp_d.split(" ")

    src_port = "".join(ramec_ftp_d_split[34:36])
    src_ports = []
    src_ports.append(str(int(src_port, 16)))

    dst_ports = []
    dst_port = "".join(ramec_ftp_d_split[36:38])
    dst_ports.append(str(int(dst_port, 16)))

    komunikacia1 = []
    komunikacia1.append(ramce_ftp_d[0])
    cisla_ramcov_komunikacie = []
    cisla_ramcov_komunikacie.append(cisla_ramcov[0])
    for i in range(1, len(ramce_ftp_d)):
        b = raw(ramce_ftp_d[i])
        # Upravenie rámca
        ramec = b.hex(" ").upper()
        ramec_split = ramec.split(" ")

        src_port = "".join(ramec_split[34:36])
        src_port_int = str(int(src_port, 16))
        dst_port = "".join(ramec_split[36:38])
        dst_port_int = str(int(dst_port, 16))

        if (src_port_int == dst_ports[0] and dst_port_int == src_ports[0]) or (src_port_int == src_ports[0] and dst_port_int == dst_ports[0]):
            komunikacia1.append(ramce_ftp_d[i])
            cisla_ramcov_komunikacie.append(cisla_ramcov[i])

    syn = 0
    fin = 0
    rst = 0
    for pkt in komunikacia1:
        b = raw(pkt)
        # Upravenie rámca
        ramec = b.hex(" ").upper()
        ramec_split = ramec.split(" ")

        flags_hex = ramec_split[47]
        flags = "{0:08b}".format(int(flags_hex, 16))

        if flags[6] == "1":
            syn = 1
        elif flags[7] == "1" and syn == 1:
            fin = fin + 1
        elif flags[5] == "1":
            rst = 1

    if syn == 1 and (fin == 2 or rst == 1):
        file_out.write("Úplná komunikácia\n")
        i = 0
        for pkt in komunikacia1:
            b = raw(pkt)
            # Upravenie rámca
            ramec = b.hex(" ").upper()
            ramec_split = ramec.split(" ")
            dlzka_ramca = len(pkt)
            dlzka_ramca_m = dlzka_ramca_po_mediu(dlzka_ramca)
            dst_mac = ":".join(ramec_split[:6])
            src_mac = ":".join(ramec_split[6:12])
            src_port = "".join(ramec_split[34:36])
            src_port_int = str(int(src_port, 16))
            dst_port = "".join(ramec_split[36:38])
            dst_port_int = str(int(dst_port, 16))
            src_IP = zdrojova_IP_f(ramec_split)
            dst_IP = cielova_IP_f(ramec_split)
            file_out.write("rámec " + str(cisla_ramcov_komunikacie[i]) + "\ndĺžka rámca poskytnutá pcap api: " + str(
                dlzka_ramca) + "\ndĺžka rámca prenášaného po médiu: " +
                           str(
                               dlzka_ramca_m) + "\n" + "Ethernet II\nZdrojová MAC adresa: " + src_mac + "\nCieľová MAC adresa: "
                           + dst_mac + "\n" + "IPv4\nZdrojová IP: " + src_IP + "\nCieľová IP: " + dst_IP + "\nTCP\n" + "FTP-DATA\nZdrojový port: " + src_port_int + "\nCieľový port: " + dst_port_int + "\n")
            vypis_ramca(dlzka_ramca, file_out, ramec_split)
            i = i + 1
    else:
        file_out.write("Neúplná komunikácia\n")
        i = 0
        for pkt in komunikacia1:
            b = raw(pkt)
            # Upravenie rámca
            ramec = b.hex(" ").upper()
            ramec_split = ramec.split(" ")
            dlzka_ramca = len(pkt)
            dlzka_ramca_m = dlzka_ramca_po_mediu(dlzka_ramca)
            dst_mac = ":".join(ramec_split[:6])
            src_mac = ":".join(ramec_split[6:12])
            src_port = "".join(ramec_split[34:36])
            src_port_int = str(int(src_port, 16))
            dst_port = "".join(ramec_split[36:38])
            dst_port_int = str(int(dst_port, 16))
            src_IP = zdrojova_IP_f(ramec_split)
            dst_IP = cielova_IP_f(ramec_split)
            file_out.write("rámec " + str(cisla_ramcov_komunikacie[i]) + "\ndĺžka rámca poskytnutá pcap api: " + str(dlzka_ramca) + "\ndĺžka rámca prenášaného po médiu: " +
                           str(dlzka_ramca_m) + "\n" + "Ethernet II\nZdrojová MAC adresa: " + src_mac + "\nCieľová MAC adresa: "
                           + dst_mac + "\n" + "IPv4\nZdrojová IP: " + src_IP + "\nCieľová IP: " + dst_IP + "\nTCP\n" + "FTP-DATA\nZdrojový port: " + src_port_int + "\nCieľový port: " + dst_port_int + "\n")
            vypis_ramca(dlzka_ramca, file_out, ramec_split)
            i = i + 1

# Doimplementácia - DNS
def DNS_f(packetlist, file_out):
    pocet = 0
    poradie = 1
    for pkt in packetlist:
        b = raw(pkt)
        # Upravenie rámca
        ramec = b.hex(" ").upper()
        ramec_split = ramec.split(" ")

        # Upravenie bytov pre zistenie, či ide o Ethernet II alebo IEEE 802.3
        pole_3 = "".join(ramec_split[12:14])
        pole_3_int = int(pole_3, 16)
        vnoreny_protokol = []
        if pole_3_int >= 1600:
            f_E = open("EtherTypes.txt", "r")
            vnoreny_protokol = filter(f_E, pole_3)
            f_E.close()

        ip_protokol = ""
        # Ak je typ Ethernet II IP - zistím a vypíšem adresy + IP protokol
        if vnoreny_protokol == "IPv4":
            f_IP = open("IPProtocolNumbers.txt", "r")
            ip_protokol = filter(f_IP, ramec_split[23])
            f_IP.close()

        if ip_protokol == "UDP":
            src_port = "".join(ramec_split[34:36])
            src_port_dec = str(int(src_port, 16))
            dst_port = "".join(ramec_split[36:38])
            dst_port_dec = str(int(dst_port, 16))
            f_udp = open("UDPports.txt", "r")
            udp_port = ""
            for line in f_udp:
                line = line.split(" ")
                if line[0] == dst_port_dec or line[0] == src_port_dec:
                    udp_port = line[1].strip()
                    break
            f_udp.close()

            if udp_port == "DNS":
                file_out.write("rámec " + str(poradie) + "\n")
                # Dĺžka rámca
                dlzka_ramca = len(pkt)
                file_out.write("dĺžka rámca poskytnutá pcap api: " + str(dlzka_ramca) + "\n")
                dlzka_ramca_m = dlzka_ramca_po_mediu(dlzka_ramca)
                file_out.write("dĺžka rámca prenášaneho po mediu: " + str(dlzka_ramca_m) + "\n")
                # MAC adresy
                dst_mac = ":".join(ramec_split[:6])
                src_mac = ":".join(ramec_split[6:12])
                file_out.write("Zdrojová MAC adresa: " + src_mac + "\n")
                file_out.write("Cieľová MAC adresa: " + dst_mac + "\n")
                file_out.write("Ethernet II\n")
                file_out.write(ip_protokol + "\n")
                src_IP = zdrojova_IP_f(ramec_split)
                dst_IP = cielova_IP_f(ramec_split)
                file_out.write("Zdrojová IP adresa: " + src_IP + "\n")
                file_out.write("Cieľová IP adresa: " + dst_IP + "\n")
                file_out.write(udp_port + "\n")
                # Výpis rámca
                vypis_ramca(dlzka_ramca, file_out, ramec_split)
                pocet = pocet + 1

        poradie = poradie + 1

    file_out.write("Počet všetkých DNS rámcov: " + str(pocet))

# Menu
moznost = input("Vyber možnosť: \n1 - výpis všetkých rámcov\n2 - HTTP komunikácia\n3 - HTTPS komunikácia\n4 - TELNET komunikácia\n5 - FTP-CONTROL komunikácia\n6 - FTP-DATA komunikácia\n7 - DNS - doimplementácia\n")
subor = input("Zadaj názov súboru: ")

pl = otvor_pcap_subor(subor)

# Súbor na výpis
f_out = open("out.txt", "w")
f_out_http = open("out_http.txt", "w")
print("Zapisujem do súboru out.txt...")

if moznost == "1":
    vsetky_ramce_f(pl, f_out)
elif moznost == "2":
    HTTP_f(pl, f_out_http)
elif moznost == "3":
    HTTPS_f(pl, f_out)
elif moznost == "4":
    TELNET_f(pl, f_out)
elif moznost == "5":
    FTP_C_f(pl, f_out)
elif moznost == "6":
    FTP_D_f(pl, f_out)
elif moznost == "7":
    DNS_f(pl, f_out)

f_out.close()
f_out_http.close()
print("Done.")