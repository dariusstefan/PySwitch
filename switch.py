#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name
from enum import Enum, auto


class SwitchState(Enum):
    STATE_INIT = 0
    STATE_LISTENING = auto()
    STATE_RECEIVED = auto()
    STATE_UNICAST = auto()
    STATE_BROADCAST = auto()


class STPPortState(Enum):
    BLOCKED_PORT = 0
    DESIGNATED_PORT = auto()
    ROOT_PORT = auto()


class InstanceData:
    def __init__(self):
        switch_priority = None
        VLAN_table = None
        CAM_table = None
        STP_table = None
        root_bridge_id = None
        root_path_cost = None
        num_interfaces = None
        current_dest_mac = None
        current_src_mac = None
        current_ethertype = None
        vlan_id = None
        input_interface = None
        output_interface = None
        packet_data = None
        packet_length = None


def do_state_init(instance_data):
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    instance_data.CAM_table = {}
    instance_data.num_interfaces = num_interfaces

    instance_data.switch_priority, instance_data.VLAN_table = config_vlan(switch_id)
    print(f"Switch priority: {instance_data.switch_priority}")
    print_vlan_table(instance_data.VLAN_table)
    print("-------------------------")

    instance_data.STP_table = {}
    instance_data.root_bridge_id = instance_data.switch_priority
    instance_data.root_path_cost = b'\x00'

    for interface in interfaces:
        if instance_data.VLAN_table[interface] == 'T':
            instance_data.STP_table[interface] = STPPortState.DESIGNATED_PORT

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec, args=[instance_data.switch_priority, instance_data.VLAN_table])
    t.start()

    return SwitchState.STATE_LISTENING


def do_state_listening(instance_data):
    # Note that data is of type bytes([...]).
    # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
    # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
    # b3 = b1[0:2] + b[3:4].
    interface, data, length = recv_from_any_link()

    dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

    instance_data.current_dest_mac = dest_mac
    instance_data.current_src_mac = src_mac
    instance_data.vlan_id = vlan_id

    instance_data.current_ethertype = ethertype
    instance_data.input_interface = interface
    instance_data.packet_data = data
    instance_data.packet_length = length

    return SwitchState.STATE_RECEIVED


def add_to_path_cost(path_cost, value):
    old_value = int.from_bytes(path_cost, byteorder='big')
    new_value = old_value + value
    return new_value.to_bytes(1, byteorder='big')


def update_STP_table(instance_data, root_bridge_id, sender_bridge_id, sender_path_cost):
    own_bridge_id = instance_data.switch_priority
    if root_bridge_id < instance_data.root_bridge_id:
        old_root_bridge_id = instance_data.root_bridge_id

        instance_data.root_bridge_id = root_bridge_id
        instance_data.root_path_cost = add_to_path_cost(sender_path_cost, 10)
        instance_data.STP_table[instance_data.input_interface] = STPPortState.ROOT_PORT

        if old_root_bridge_id == own_bridge_id:
            for port in instance_data.STP_table:
                if instance_data.STP_table[port] != STPPortState.ROOT_PORT:
                    instance_data.STP_table[port] = STPPortState.BLOCKED_PORT
        
        new_bdpu = make_bdpu(root_bridge_id, own_bridge_id, instance_data.root_path_cost)
        for port in instance_data.VLAN_table:
            if instance_data.VLAN_table[port] == 'T':
                send_to_link(port, new_bdpu, len(new_bdpu))
    elif root_bridge_id == instance_data.root_bridge_id:
        if instance_data.STP_table[instance_data.input_interface] == STPPortState.ROOT_PORT:
            if add_to_path_cost(sender_path_cost, 10) < instance_data.root_path_cost:
                instance_data.root_path_cost = add_to_path_cost(sender_path_cost, 10)
        else:
            if sender_path_cost > instance_data.root_path_cost:
                instance_data.STP_table[instance_data.input_interface] = STPPortState.DESIGNATED_PORT
    elif sender_bridge_id == own_bridge_id:
        instance_data.STP_table[instance_data.input_interface] = STPPortState.BLOCKED_PORT
    
    if own_bridge_id == root_bridge_id:
        for port in instance_data.STP_table:
            instance_data.STP_table[port] = STPPortState.DESIGNATED_PORT


def do_state_received(instance_data):
    if is_bdpu(instance_data.current_dest_mac):
        root_bridge_id, sender_bridge_id, sender_path_cost = parse_bdpu(instance_data.packet_data)
        update_STP_table(instance_data, root_bridge_id, sender_bridge_id, sender_path_cost)
        return SwitchState.STATE_LISTENING
    
    instance_data.CAM_table[instance_data.current_src_mac] = instance_data.input_interface

    if is_unicast(instance_data.current_dest_mac):
        if instance_data.current_dest_mac in instance_data.CAM_table:
            instance_data.output_interface = instance_data.CAM_table[instance_data.current_dest_mac]
            return SwitchState.STATE_UNICAST
        else:
            return SwitchState.STATE_BROADCAST
    else:
        return SwitchState.STATE_BROADCAST
    

def do_state_unicast(instance_data):
    forward_packet(instance_data, instance_data.input_interface, instance_data.output_interface)
    return SwitchState.STATE_LISTENING


def do_state_broadcast(instance_data):
    for interface in range(instance_data.num_interfaces):
        if interface != instance_data.input_interface:
            forward_packet(instance_data, instance_data.input_interface, interface)
    return SwitchState.STATE_LISTENING


def forward_packet(instance_data, input_iface, output_iface):
    if instance_data.VLAN_table[input_iface] == 'T':
        if instance_data.VLAN_table[output_iface] == 'T' and instance_data.STP_table[output_iface] != STPPortState.BLOCKED_PORT:
            send_to_link(output_iface, instance_data.packet_data, instance_data.packet_length)
        else:
            if instance_data.VLAN_table[output_iface] == instance_data.vlan_id:
                new_packet = instance_data.packet_data[0:12] + instance_data.packet_data[16:]
                send_to_link(output_iface, new_packet, instance_data.packet_length - 4)
    else:
        input_vlan = instance_data.VLAN_table[input_iface]
        if instance_data.VLAN_table[output_iface] == 'T' and instance_data.STP_table[output_iface] != STPPortState.BLOCKED_PORT:
            new_packet = instance_data.packet_data[0:12] + create_vlan_tag(input_vlan) + instance_data.packet_data[12:]
            send_to_link(output_iface, new_packet, instance_data.packet_length + 4)
        else:
            if instance_data.VLAN_table[output_iface] == input_vlan:
                send_to_link(output_iface, instance_data.packet_data, instance_data.packet_length)


state_functions = {
    SwitchState.STATE_INIT: do_state_init,
    SwitchState.STATE_LISTENING: do_state_listening,
    SwitchState.STATE_RECEIVED: do_state_received,
    SwitchState.STATE_UNICAST: do_state_unicast,
    SwitchState.STATE_BROADCAST: do_state_broadcast,
}


def run_state(state, instance_data):
    return state_functions[state](instance_data)


def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id


def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)


def send_bdpu_every_sec(bridge_id, VLAN_table):
    while True:
        sender_path_cost = b'\x00'
        bdpu = make_bdpu(bridge_id, bridge_id, sender_path_cost)
        for port in VLAN_table:
            if VLAN_table[port] == 'T':
                send_to_link(port, bdpu, len(bdpu))
        time.sleep(1)


def is_unicast(mac):
    first_byte = mac[0]
    return (first_byte & 0x01) == 0


def is_bdpu(mac):
    return mac == b'\x01\x80\xc2\x00\x00\x00'


def print_mac(mac):
    print(':'.join(f'{b:02x}' for b in mac))


def print_cam_table(cam_table):
    for key, value in cam_table.items():
        print(f"MAC: {':'.join(f'{b:02x}' for b in key)}, Interface: {value}")


def config_vlan(switch_id):
    VLAN_table = {}
    path = f"./configs/switch{switch_id}.cfg"
    with open(path, "r") as file:
        switch_priority = int(file.readline().strip())
        switch_priority = switch_priority.to_bytes(2, byteorder='big')
        interface_number = 0
        for line in file:
            _, vlan = line.strip().split()
            VLAN_table[interface_number] = vlan if vlan == 'T' else int(vlan)
            interface_number += 1
        return switch_priority, VLAN_table
    
    
def print_vlan_table(vlan_table):
    print("VLAN table:")
    for interface, vlan in vlan_table.items():
        print(f"Interface: {interface}, VLAN: {vlan}")


def print_stp_table(stp_table):
    print("STP table:")
    for interface, state in stp_table.items():
        print(f"Interface: {interface}, State: {state}")


def make_bdpu(root_bridge_id, sender_bridge_id, sender_path_cost):
    dst_mac = b'\x01\x80\xc2\x00\x00\x00'
    src_mac = get_switch_mac()
    llc_header = b'\x42\x42\x03'
    bdpu_header = b'\x00\x00\x00\x00'
    llc_length = 12
    llc_length = llc_length.to_bytes(2, byteorder='big')

    return dst_mac + src_mac + llc_length + llc_header + bdpu_header + root_bridge_id + sender_bridge_id + sender_path_cost

def parse_bdpu(data):
    root_bridge_id = data[21:23]
    sender_bridge_id = data[23:25]
    sender_path_cost = data[25].to_bytes(1, byteorder='big')
    return root_bridge_id, sender_bridge_id, sender_path_cost

instance_data = InstanceData()


def main():
    current_state = SwitchState.STATE_INIT

    while True:
        current_state = run_state(current_state, instance_data)


if __name__ == "__main__":
    main()
