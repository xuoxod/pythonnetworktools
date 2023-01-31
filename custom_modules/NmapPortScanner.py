import nmap
from multiprocessing.pool import ThreadPool
from .ConsoleMessenger import CONSOLE_MESSENGER_SWITCH as cms
from .PlatformConstants import LINE_SEP as lsep

cus = cms["custom"]


def scan_host_port(host, port):
    print("Scanning host {} on port {}".format(host, port))
    nm_scanner = nmap.PortScanner()
    nm_scanner.scan(host, str(port))
    return nm_scanner


def scan_network_hosts_port(network, port):
    print("Scanning network {} host's port {}".format(network, port))
    nm = nmap.PortScanner()
    nm_scanner_results = nm.scan(network, str(port))
    return nm_scanner_results


def custom_scan_network_hosts_port(network, port, scan_mode):
    return_list = []
    nm = nmap.PortScanner()
    a = nm.scan(hosts=network, ports=str(port), arguments=scan_mode)
    for k, v in a["scan"].items():
        if str(v["status"]["state"]) == "up":
            try:
                return_list.append(
                    "{},{},{}".format(
                        str(v["status"]["state"]),
                        str(v["addresses"]["ipv4"]),
                        str(v["addresses"]["mac"]),
                    )
                )
            except Exception:
                pass
    if len(return_list) > 0:
        return {"status": True, "data": return_list, "source": a}
    else:
        return {"status": False, "reason": "Failed to detect any hosts"}


def scan_host_port_thread(host, port, num_proc=3):
    _processes = num_proc
    pool = ThreadPool(processes=_processes)
    async_result = pool.apply_async(scan_host_port, (host, port))
    return async_result.get()


def scan_network_hosts_port_thread(network, port):
    pool = ThreadPool(processes=3)
    async_results = pool.apply_async(scan_network_hosts_port, (network, port))
    return async_results.get()


def custom_scan_network_hosts_port_thread(network, port, scan_mode):
    pool = ThreadPool(processes=3)
    async_results = pool.apply_async(
        custom_scan_network_hosts_port, (network, port, scan_mode)
    )
    return async_results.get()


def handle_results(results):
    nmap = results["nmap"]
    scan = results["scan"]
    tcp = None

    command_line = nmap["command_line"]
    scan_method = nmap["scaninfo"]["tcp"]["method"]
    scan_ports = nmap["scaninfo"]["tcp"]["services"]
    scan_time = nmap["scanstats"]["timestr"]
    scan_elapsed_time = nmap["scanstats"]["elapsed"]
    detected_hosts_count = nmap["scanstats"]["uphosts"]

    print("       Command:\t\t{}".format(command_line))
    print("     Scan Type:\t\t{}".format(scan_method))
    print(" Scanned ports:\t\t{}".format(scan_ports))
    print("          Time:\t\t{}".format(scan_time))
    print("  Elapsed Time:\t\t{}".format(scan_elapsed_time))
    print("Hosts Detected:\t\t{}".format(detected_hosts_count))
    print("-" * 100)

    for ip in scan:
        address = ip
        print("Host:\t\t{}:".format(address))

        hostnames = scan[address]["hostnames"][0]
        name = hostnames["name"]
        type = hostnames["type"]
        vendor = scan[address]["vendor"]
        status = scan[address]["status"]["state"]
        response_type = scan[address]["status"]["reason"]
        
        if "tcp" in scan[address]:
            tcp = scan[address]['tcp']
            
        if name:
            print("  Host name:\t\t{}".format(name))
        print("  Host Type:\t\t{}".format(type))
        if vendor:
            print("     Vendor:\t\t{}".format(vendor))
        print("Host status:\t\t{}".format(status))
        print("Reason Type:\t\t{}".format(response_type))
        if tcp:
            for p in tcp:
                port = p
                port_state = tcp[port]['state']
                port_name = tcp[port]['name']
                product = tcp[port]['product']
                product_version = tcp[port]['version']
                extrainfo = tcp[port]['extrainfo']
                conf = tcp[port]['conf']
                cpe = tcp[port]['cpe']
                print("       Port:\t\t{}".format(p))
                print("                  Conf:\t\t{}".format(conf))
                
                if cpe:
                    print("                   CPE:\t\t{}".format(cpe))
                    
                print("                 State:\t\t{}".format(port_state))
                print("                  Name:\t\t{}".format(port_name))
                
                if extrainfo:
                    print("            Extra Info:\t\t{}".format(extrainfo))
                
                if product:
                    print("               Product:\t\t{}".format(product))
                    
                if product_version:
                    print("               Version:\t\t{}".format(product_version))
                print("\n")
        print("\n")


def _handle_results(results):
    print("Handling results {}".format(results))
    protocols = None
    command = None
    scan_info = None
    dict_tcp_keys = None
    csv = None
    tcp = None
    state = None
    product = None
    reason = None
    name = None
    version = None
    extra = None
    conf = None

    # results = ipo(hosts, ports, verbose, timeout, report)

    """if results[host].state:
        state = results[host].state()

    if results[host].all_protocols:
        protocols = results[host].all_protocols()

    if results.command_line:
        command = results.command_line()

    if results.scaninfo:
        scan_info = results.scaninfo()

    if "tcp" in results[host]:
        dict_tcp_keys = results[host]["tcp"].keys()

    if results.csv:
        csv = results.csv"""

    if not results == None:
        if "all_hosts" in results:
            all_hosts = results.all_hosts()
            print("All hosts {}".format(all_hosts))

            for _host in all_hosts:

                if results[_host].state:
                    state = results[_host].state()

                if results[_host].all_protocols:
                    protocols = results[_host].all_protocols()

                if results.command_line:
                    command = results.command_line()

                if results.scaninfo:
                    scan_info = results.scaninfo()

                if "tcp" in results[_host]:
                    dict_tcp_keys = results[_host]["tcp"].keys()

                if results.csv:
                    csv = results.csv()

                print("-" * 100 + "\n")

                print("Host:\t{}".format(_host))

                print("State:\t{}".format(state))

                print("Command:\t{}".format(command))

                print("Scann Info:\t{}".format(scan_info))

                # print("CSV:\t{}".format(csv))

                # print("-" * 100 + "\n\n")

                if protocols:

                    for protocol in protocols:
                        info = scan_info[protocol]

                        print("Protocol:\t{}".format(protocol))

                        print(
                            "Scan Info =\t\tAction: {}\tPorts: {}".format(
                                info["method"], info["services"]
                            )
                        )

                        if protocol == "tcp":

                            dict_tcp_keys = results[_host][protocol].keys()

                            print("Open Ports")

                            print(*dict_tcp_keys, sep="\t")

                            print("\n")

                            for tcp_key in dict_tcp_keys:
                                key = results[_host][protocol][tcp_key]

                                # print("TCP Key:\t{}".format(key))

                                state = key["state"]
                                reason = key["reason"]
                                product = key["product"]
                                name = key["name"]
                                version = key["version"]
                                extra = key["extrainfo"]
                                conf = key["conf"]
                                cpe = key["cpe"]

                                print("Port:\t\t{}".format(tcp_key))

                                print("State:\t\t{}".format(state))

                                print("Reason:\t\t{}".format(reason))

                                print("Name:\t\t{}".format(name))

                                print("Product:\t\t{}".format(product))

                                print("Version:\t\t{}".format(version))

                                print("Extra:\t\t{}".format(extra))

                                print("Conf:\t\t{}".format(conf))

                                print("CPE:\t\t{}\n".format(cpe))
    else:
        msg_header = cus(133, 134, 223, "Alert:")
        msg_body = cus(255, 255, 255, "No hosts were detected")
        msg = "{}\t{}{}".format(msg_header, msg_body, lsep)
        print("{}".format(msg))
