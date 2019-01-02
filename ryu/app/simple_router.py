import logging
import struct
from operator import attrgetter
import copy
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import ipv6
from ryu.lib.packet import ether_types
from ryu.lib import hub
from ryu import utils

from ryu.topology import event
from ryu.topology.api import get_switch, get_link
from ryu.app import setting


class SimpleRouter(app_manager.RyuApp):
    """
    a simple router app
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _NAME = 'SimpleRouter'

    def __init__(self, *args, **kwargs):
        super(SimpleRouter, self).__init__(*args, **kwargs)
        self.name = "simplerouter"
        self.mac_to_port = {}  # the dictionary to record the macaddress and  the port. {macaddress:port}
        self.topology_api_app = self  # call the API of ryu to get the topology
        self.switches = []  # the list to save the switches
        self.link_list = []  # the links of the topology
        self.datapaths = {}  # the dictionary of the datapath. {datapath.id: datapath}
        # the dictionary to save the link information of the port.
        # {link(src,dst):(src_port,dst_port)}
        self.link_to_port = {}
        self.pre_link_to_port = {}
        # record the dictionary of the access link infos of the switch
        # {(dpid, port): host_ip}
        self.access_table = {}
        self.pre_access_table = {}
        # the dictionary of the switches and the ports info
        # {switch(dpid):[portnum, portnum]}
        self.switch_port_table = {}
        # the access ports of the switch by the host.
        # {switch(dpid):[portnum, portnum]}
        self.access_ports = {}
        # the inter ports between two switches
        # {switch(dpid):[portnum, portnum]}
        self.inter_ports = {}
        # network matrix
        # {src_dpid:{dst_dpid:{"weight":weight, "bandwidth":bandwidth}}}
        self.graph = {}  # the topology of the network
        self.pre_graph = {}
        # to save the shortest path of the graph.
        # {(src_sw, dst_sw):[sw1, sw2,..]}
        self.shortest_path = {}
        self.discover_thread = hub.spawn(self._discover)

    def _discover(self):
        """
        to discover the network resource periodically
        :return:
        """
        i = 0
        while True:
            self.show_topology()
            if i == 5:
                self.get_topology(None)
                i = 0
            hub.sleep(setting.DISCOVERY_PERIOD)
            i += 1

    def show_topology(self):
        """
        the function to show the network topology
        :return:
        """
        if self.pre_graph != self.graph and setting.TOSHOW:
            print("---------------------Topo Link---------------------")
            print("%10s" % "switch", end=" ")
            for i in self.graph.keys():
                print("%10d" % i, end="")
            print("")
            for i in self.graph.keys():
                print("%10d" % i, end="")
                for j in self.graph[i].values():
                    print("%10.0f" % j['weight'], end="")
                print("")
            self.pre_graph = copy.deepcopy(self.graph)

        if self.pre_link_to_port != self.link_to_port and setting.TOSHOW:
            print("---------------------Link Port---------------------")
            print("%10s" % "switch", end="")
            for i in self.graph.keys():
                print("%10d" % i, end="")
            print("")
            for i in self.graph.keys():
                print("%10d" % i, end="")
                for j in self.graph.keys():
                    if (i, j) in self.link_to_port.keys():
                        print("%10s" % str(self.link_to_port[(i, j)]), end="")
                    else:
                        print("%10s" % "No-link", end="")
                print("")
            self.pre_link_to_port = copy.deepcopy(self.link_to_port)

        if self.pre_access_table != self.access_table and setting.TOSHOW:
            print("----------------Access Host-------------------")
            print("%10s, %12s" % ("switch", "Host"))
            if not self.access_table.keys():
                print("    NO found host")
            else:
                for tup in self.access_table:
                    print('%10d: %12s' % (tup[0], self.access_table[tup]))
            self.pre_access_table = copy.deepcopy(self.access_table)

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        """
        erroe handler
        :param ev:
        :return:
        """
        msg = ev.msg
        self.logger.info('OFPErrorMsg received: type=0x%02x code=0x%02x '
                          'message=%s, datapath:%s', msg.type, msg.code,
                          utils.hex_array(msg.data), msg.datapath.id)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """
        handle the event when the state of a switch changed, such as
        connects the controller or shutdown the connection
        :param ev:
        :return:
        """
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            # handle the event when a new switch connected to the controller, register it and
            # save the datapath to the datapaths list
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            # handle the event when a switch shut down the link to the controller,
            # unregister it and remove it  from the datapaths list
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def add_flow_test(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        """
        add a flow entry to the switch
        :param datapath:
        :param priority:
        :param match:
        :param actions:
        :param buffer_id:
        :param idle_timeout:
        :param hard_timeout:
        :return:
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, buffer_id=buffer_id,
                                    idle_timeout=idle_timeout, hard_timeout=hard_timeout,
                                    match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    idle_timeout=idle_timeout, hard_timeout=hard_timeout,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        """
        add a flow entry to the switch
        :param datapath:
        :param priority:
        :param match:
        :param actions:
        :param idle_timeout:
        :param hard_timeout:
        :return:
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                idle_timeout=idle_timeout, hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def del_flow(self, datapath, match):
        """
        clear the flow entry of switch
        :param datapath:
        :return:
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        cookie = cookie_mask = 0
        table_id = 0
        idle_timeout = 15
        hard_timeout = 60
        priority = 1
        buffer_id = ofproto.OFP_NO_BUFFER
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        req = parser.OFPFlowMod(datapath=datapath, cookie=cookie, cookie_mask=cookie_mask,
                                table_id=table_id, command=ofproto.OFPFC_DELETE,
                                idle_timeout=0, hard_timeout=0,
                                priority=1, out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPP_ANY,
                                buffer_id=ofproto.OFP_NO_BUFFER,
                                flags=ofproto.OFPFF_SEND_FLOW_REM, match=match, instructions=inst)
        datapath.send_msg(req)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        handle the switch events when a switch connected to the controller,
        install a table miss flow entry to the switch
        :param ev:
        :return:
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        msg = ev.msg
        self.logger.info("switch:%s connected", datapath.id)

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def install_flow_test(self, datapath, path, flow_info, buffer_id, data):

        eth_type, ip_src, ip_dst, in_port = flow_info
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        assert path

        if len(path) >= 2:
            # if the shortest path have two or more switches
            if datapath == self.datapaths[path[0]]:
                # the  first flow entry
                port_pair = self.get_link2port(path[0], path[1])
                out_port = port_pair[0]

                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port=in_port, eth_type=eth_type,
                                        ipv4_src=ip_src, ipv4_dst=ip_dst)
                self.add_flow(datapath, 1, match, actions)
                # first pkt_out
                actions = [parser.OFPActionOutput(out_port)]
                msg_data = None
                if buffer_id == ofproto.OFP_NO_BUFFER:
                    msg_data = data

                out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
                                          data=msg_data, in_port=in_port, actions=actions)
                datapath.send_msg(out)

            elif datapath == self.datapaths[path[-1]]:
                # the last hop: tor -> host
                port_pair = self.get_link2port(path[-2], path[-1])
                in_port = port_pair[0]
                dst_port = None

                for key in self.access_table.keys():
                    if ip_dst == self.access_table[key]:
                        dst_port = key[1]
                        break

                actions = [parser.OFPActionOutput(dst_port)]
                match = parser.OFPMatch(in_port=in_port, eth_type=eth_type,
                                        ipv4_src=ip_src, ipv4_dst=ip_dst)
                self.add_flow(datapath, 1, match, actions)

                # last pkt_out
                actions = [parser.OFPActionOutput(dst_port)]
                msg_data = None
                if buffer_id == ofproto.OFP_NO_BUFFER:
                    msg_data = data

                out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
                                          data=msg_data, in_port=in_port, actions=actions)

                datapath.send_msg(out)
            else:
                # inter links flow entry
                index = path.index(datapath.id)
                port_pair = self.get_link2port(path[index-1], path[index])
                port_pair_next = self.get_link2port(path[index], path[index+1])
                in_port = port_pair[1]
                out_port = port_pair_next[0]
                actions = [parser.OFPActionOutput(out_port)]

                match = parser.OFPMatch(in_port=in_port, eth_type=eth_type,
                                        ipv4_src=ip_src, ipv4_dst=ip_dst)
                self.add_flow(datapath, 1, match, actions)
                # inter links pkt_out
                msg_data = None
                if buffer_id == ofproto.OFP_NO_BUFFER:
                    msg_data = data

                out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
                                          data=msg_data, in_port=in_port, actions=actions)
                datapath.send_msg(out)

        else:
            # if the shortest path have only one switch
            out_port = None
            for key in self.access_table.keys():
                if ip_dst == self.access_table[key]:
                    out_port = key[1]
                    break

            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(in_port=in_port, eth_type=eth_type,
                                    ipv4_src=ip_src, ipv4_dst=ip_dst)
            self.add_flow(datapath, 1, match, actions)

            msg_data = None
            if buffer_id == ofproto.OFP_NO_BUFFER:
                msg_data = data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
                                      data=msg_data, in_port=in_port, actions=actions)

            datapath.send_msg(out)

    def install_flow(self, path, flow_info, buffer_id, data):
        '''
            path=[dpid1, dpid2, dpid3...]
            flow_info=(eth_type, src_ip, dst_ip, in_port)
        '''
        # first flow entry
        in_port = flow_info[3]
        assert path
        datapath_first = self.datapaths[path[0]]
        ofproto = datapath_first.ofproto
        parser = datapath_first.ofproto_parser
        out_port = ofproto.OFPP_LOCAL

        # inter_link
        if len(path) >= 2:
            for i in range(1, len(path) - 1):
                port = self.get_link2port(path[i - 1], path[i])
                port_next = self.get_link2port(path[i], path[i + 1])
                if port:
                    src_port, dst_port = port[1], port_next[0]
                    datapath = self.datapaths[path[i]]
                    ofproto = datapath.ofproto
                    parser = datapath.ofproto_parser
                    actions = [parser.OFPActionOutput(dst_port)]

                    match = parser.OFPMatch(in_port=src_port, eth_type=flow_info[0],
                                            ipv4_src=flow_info[1], ipv4_dst=flow_info[2])
                    """if buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions, buffer_id=buffer_id,
                                      idle_timeout=10, hard_timeout=30)
                    else:
                        self.add_flow(datapath, 1, match, actions,
                                      idle_timeout=10, hard_timeout=30)"""
                    self.add_flow(datapath, 1, match, actions,
                                  idle_timeout=100, hard_timeout=300)
                    print("add the flow entry to the switches")

                    # inter links pkt_out
                    msg_data = None
                    if buffer_id == ofproto.OFP_NO_BUFFER:
                        msg_data = data

                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
                                              data=msg_data, in_port=src_port, actions=actions)
                    datapath.send_msg(out)
                    print("inter links pkt-out")

        if len(path) > 1:
            # the  first flow entry
            port_pair = self.get_link2port(path[0], path[1])
            out_port = port_pair[0]

            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(in_port=in_port, eth_type=flow_info[0],
                                    ipv4_src=flow_info[1], ipv4_dst=flow_info[2])
            """if buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath_first, 1, match, actions,
                              buffer_id=buffer_id, idle_timeout=10, hard_timeout=30)
            else:
                self.add_flow(datapath_first, 1, match, actions,
                              idle_timeout=10, hard_timeout=30)"""
            self.add_flow(datapath_first, 1, match, actions,
                          idle_timeout=100, hard_timeout=300)
            print("add the flow entry to the switch which links to the first host")

            # the last hop: tor -> host
            datapath = self.datapaths[path[-1]]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            src_port = self.get_link2port(path[-2], path[-1])[1]
            dst_port = None

            for key in self.access_table.keys():
                if flow_info[2] == self.access_table[key]:
                    dst_port = key[1]
                    break

            actions = [parser.OFPActionOutput(dst_port)]
            match = parser.OFPMatch(in_port=src_port, eth_type=flow_info[0],
                                    ipv4_src=flow_info[1], ipv4_dst=flow_info[2])
            self.add_flow(datapath, 1, match, actions,
                          idle_timeout=100, hard_timeout=300)

            print("add the flow entry to the switch which links to the last host")

            # first pkt_out
            actions = [parser.OFPActionOutput(out_port)]
            msg_data = None
            if buffer_id == ofproto.OFP_NO_BUFFER:
                msg_data = data

            out = parser.OFPPacketOut(datapath=datapath_first, buffer_id=buffer_id,
                                      data=msg_data, in_port=in_port, actions=actions)
            datapath_first.send_msg(out)
            print("inter link between the host and switch pkt-out")

            # last pkt_out
            """actions = [parser.OFPActionOutput(dst_port)]
            msg_data = None
            if buffer_id == ofproto.OFP_NO_BUFFER:
                msg_data = data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
                                      data=msg_data, in_port=src_port, actions=actions)

            datapath.send_msg(out)"""

            print("inter link between the switch and the host pkt-out")

        else:  # src and dst on the same
            out_port = None
            for key in self.access_table.keys():
                if flow_info[2] == self.access_table[key]:
                    out_port = key[1]
                    break

            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(in_port=in_port, eth_type=flow_info[0],
                                    ipv4_src=flow_info[1], ipv4_dst=flow_info[2])
            """if buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath_first, 1, match, actions, buffer_id=buffer_id,
                              idle_timeout=10, hard_timeout=30)
            else:
                self.add_flow(datapath_first, 1, match, actions,
                              idle_timeout=10, hard_timeout=30)"""
            self.add_flow(datapath_first, 1, match, actions,
                          idle_timeout=100, hard_timeout=300)
            print("add the flow entry to the switch when the two host link to the same switch")

            # pkt_out
            msg_data = None
            if buffer_id == ofproto.OFP_NO_BUFFER:
                msg_data = data

            out = parser.OFPPacketOut(datapath=datapath_first, buffer_id=buffer_id,
                                      data=msg_data, in_port=in_port, actions=actions)

            datapath_first.send_msg(out)
            print("pkt-out when the two host link to the same switch")

    def get_host_location(self, host_ip):
        """
        the function to get the host location through the ip address
        :param host_ip:
        :return:
        """
        for key in self.access_table:
            if self.access_table[key] == host_ip:
                return key
        self.logger.info("%s location no found." % host_ip)
        return None

    def get_switches(self):
        """
        get all the switches
        :return:
        """
        return self.switches

    def get_links(self):
        """
        get all the links of the ports
        :return:
        """
        return self.link_to_port

    def get_graph(self, link_list):
        """
        construct the link matrix through the link_list of the switches
        :param link_list:
        :return:
        """

        for src in self.switches:
            for dst in self.switches:
                self.graph.setdefault(src, {dst: {'weight': float('inf')}})

                if src == dst:
                    self.graph[src][src] = {'weight': 0}
                elif (src, dst) in link_list:
                    self.graph[src][dst] = {'weight': 1}
                else:
                    self.graph[src][dst] = {'weight': float('inf')}

        return self.graph

    def get_path(self, graph, src):
        """
        get the shortest path in the graph from the src ip
        :param graph:
        :param src:
        :return:
        """
        result = self.dijkstra(graph, src)
        if result:
            path = result[1]
            return path
        self.logger.info("Path no found.")
        return None

    def get_link2port(self, src_dpid, dst_dpid):
        """
        get the link information of the port
        :param src_dpid:
        :param dst_dpid:
        :return:
        """
        if (src_dpid, dst_dpid) in self.link_to_port:
            return self.link_to_port[(src_dpid, dst_dpid)]
        else:
            self.logger.info("Link to port no found.")
            return None

    def create_port_map(self, switch_list):
        """
        create the port map of the switch
        :param switch_list:
        :return:
        """
        for sw in switch_list:
            dpid = sw.dp.id
            self.switch_port_table.setdefault(dpid, set())
            self.inter_ports.setdefault(dpid, set())
            self.access_ports.setdefault(dpid, set())

            for p in sw.ports:
                self.switch_port_table[dpid].add(p.port_no)

    def create_inter_links(self, link_list):
        """
        create the inter links between the switches
        :param link_list:
        :return:
        """
        for link in link_list:
            self.link_to_port[(link.src.dpid, link.dst.dpid)] = (link.src.port_no,
                                                                 link.dst.port_no)
            self.link_to_port[(link.dst.dpid, link.src.dpid)] = (link.dst.port_no,
                                                                 link.src.port_no)

            self.link_list.append(link)

            # find the access ports and inter ports
            if link.src.dpid in self.switches:
                self.inter_ports[link.src.dpid].add(link.src.port_no)
            if link.dst.dpid in self.switches:
                self.inter_ports[link.dst.dpid].add(link.dst.port_no)

    def create_access_ports(self):
        """
        create the access ports of the switches
        :return:
        """
        for sw in self.switch_port_table:
            self.access_ports[sw] = self.switch_port_table[sw] - self.inter_ports[sw]

    @set_ev_cls(event.EventSwitchEnter, [MAIN_DISPATCHER])
    def get_topology(self, ev):
        """
        handle the event when a new switch add into the network or leave the network
        :param ev:
        :return:
        """
        switch_list = get_switch(self.topology_api_app, None)
        self.create_port_map(switch_list)
        self.switches = self.switch_port_table.keys()

        links = get_link(self.topology_api_app, None)
        self.create_inter_links(links)
        self.create_access_ports()

        self.get_graph(self.link_to_port.keys())

        if self.shortest_path:
            for (src_sw, dst_sw) in self.shortest_path:
                distance_graph, path = self.dijkstra(self.graph, src=src_sw)
                path[src_sw][dst_sw].insert(0, src_sw)
                self.shortest_path[(src_sw, dst_sw)] = path[src_sw][dst_sw]

    @set_ev_cls(event.EventLinkDelete, [MAIN_DISPATCHER])
    def update_delete_link_topology(self, ev):
        """
        update the topology when delete the link
        :param ev:
        :return:
        """
        src_sw = ev.link.src.dpid
        dst_sw = ev.link.dst.dpid
        src_port_no = ev.link.src.port_no
        dst_port_no = ev.link.dst.port_no

        if (src_sw, dst_sw) in self.link_to_port.keys():
            del self.link_to_port[(src_sw, dst_sw)]
        if (src_sw, dst_sw) in self.link_to_port.keys():
            del self.link_to_port[(dst_sw, src_sw)]

        # update the switch_port_table
        if src_port_no in self.switch_port_table[src_sw]:
            self.switch_port_table[src_sw].remove(src_port_no)
        if dst_port_no in self.switch_port_table[dst_sw]:
            self.switch_port_table[dst_sw].remove(dst_port_no)
        # update the inter link between the switches
        if src_port_no in self.inter_ports[src_sw]:
            self.inter_ports[src_sw].remove(src_port_no)
        if dst_port_no in self.inter_ports[dst_sw]:
            self.inter_ports[dst_sw].remove(dst_port_no)
        # update the access ports
        self.create_access_ports()

        self.get_graph(self.link_to_port.keys())

        if self.shortest_path:
            for (src_sw, dst_sw) in self.shortest_path:
                oldpath = self.shortest_path[(src_sw, dst_sw)]
                for switch in oldpath:
                    if switch in self.datapaths.keys():
                        datapath = self.datapaths[switch]
                        parser = datapath.ofproto_parser
                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP)
                        self.del_flow(datapath, match)

                distance_graph, path = self.dijkstra(self.graph, src=src_sw)
                path[src_sw][dst_sw].insert(0, src_sw)
                self.shortest_path[(src_sw, dst_sw)] = path[src_sw][dst_sw]

        self.shortest_path.clear()

    @set_ev_cls(event.EventLinkAdd, [MAIN_DISPATCHER])
    def update_add_link_topology(self, ev):
        """
        update the link graph of the links when add a link to the topology
        :param ev:
        :return:
        """
        links = get_link(self.topology_api_app, None)
        self.create_inter_links(links)
        self.create_access_ports()

        self.get_graph(self.link_to_port.keys())

        if self.shortest_path:
            for (src_sw, dst_sw) in self.shortest_path:
                distance_graph, path = self.dijkstra(self.graph, src=src_sw)
                path[src_sw][dst_sw].insert(0, src_sw)
                self.shortest_path[(src_sw, dst_sw)] = path[src_sw][dst_sw]

        self.shortest_path.clear()

    def dijkstra(self, graph, src):
        """
        get the shortest path through the dijkstra
        :param graph:
        :param src:
        :return:
        """
        if graph == None:
            self.logger.info("Graph is empty.")
            return None
        length = len(graph)
        type_ = type(graph)
        # Initiation
        if type_ == list:
            nodes = [i for i in range(length)]
        elif type_ == dict:
            nodes = list(graph.keys())
        visited = [src]
        path = {src: {src: []}}
        if src not in nodes:
            self.logger.info("Src no in nodes.")
            return None
        else:
            nodes.remove(src)
        distance_graph = {src: 0}
        pre = next = src
        no_link_value = 100000

        while nodes:
            distance = no_link_value
            for v in visited:
                for d in nodes:
                    new_dist = graph[src][v]['weight'] + graph[v][d]['weight']
                    if new_dist <= distance:
                        distance = new_dist
                        next = d
                        pre = v
                        graph[src][d]['weight'] = new_dist

            if distance < no_link_value:
                path[src][next] = [i for i in path[src][pre]]
                path[src][next].append(next)
                distance_graph[next] = distance
                visited.append(next)
                nodes.remove(next)
            else:
                self.logger.info("Next node no found.")
                return None
        return distance_graph, path

    '''
    In packet_in handler, we need to learn access_table by ARP.
    Therefore, the first packet from UNKOWN host MUST be ARP.
    '''
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocols(ethernet.ethernet)[0]
        eth_type = eth.ethertype

        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocols(ipv4.ipv4)

        if eth_type == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        if pkt.get_protocol(ipv6.ipv6):  # Drop the IPV6 Packets.
            match = parser.OFPMatch(eth_type=eth.ethertype)
            actions = []
            self.add_flow(datapath, 1, match, actions)
            return None

        if arp_pkt:
            self.handle_arp(arp_pkt, msg)

        if ip_pkt:
            self.handle_ip(ip_pkt, msg, eth_type)

    def handle_arp(self, arp_pkt, msg):
        """
        handle the arp packet
        :param arp_pkt:
        :param msg:
        :return:
        """
        datapath = msg.datapath
        arp_src_ip = arp_pkt.src_ip
        arp_dst_ip = arp_pkt.dst_ip
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # record the access info
        if in_port in self.access_ports[datapath.id]:
            self.access_table[(datapath.id, in_port)] = arp_src_ip

        result = self.get_host_location(arp_dst_ip)
        if result:  # host record in access table.
            datapath_dst, out_port = result[0], result[1]
            actions = [parser.OFPActionOutput(out_port)]
            datapath = self.datapaths[datapath_dst]

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=msg.data)
            datapath.send_msg(out)
        else:  # access info is not existed. send to all host.
            for dpid in self.access_ports:
                for port in self.access_ports[dpid]:
                    if (dpid, port) not in self.access_table.keys():
                        actions = [parser.OFPActionOutput(port)]
                        datapath = self.datapaths[dpid]
                        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=msg.data)
                        datapath.send_msg(out)

    def handle_ip(self, ip_pkt, msg, eth_type):

        datapath = msg.datapath
        ip_src = ip_pkt[0].src
        ip_dst = ip_pkt[0].dst
        src_sw = None
        dst_sw = None
        in_port = msg.match['in_port']

        src_location = self.get_host_location(ip_src)
        dst_location = self.get_host_location(ip_dst)

        if src_location and dst_location:
            src_sw = src_location[0]
            dst_sw = dst_location[0]
        else:
            self.get_topology(None)
            return

        if (src_sw, dst_sw) not in self.shortest_path.keys():
            result = self.dijkstra(self.graph, src_sw)
            path = result[1][src_sw][dst_sw]
            path.insert(0, src_sw)
            self.shortest_path[(src_sw, dst_sw)] = path
            flow_info = (eth_type, ip_src, ip_dst, in_port)
            self.install_flow_test(datapath, path, flow_info, msg.buffer_id, msg.data)
        else:
            path = self.shortest_path[(src_sw, dst_sw)]
            flow_info = (eth_type, ip_src, ip_dst, in_port)
            self.install_flow_test(datapath, path, flow_info, msg.buffer_id, msg.data)
