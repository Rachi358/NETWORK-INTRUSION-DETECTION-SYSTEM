"""
Real-time packet capture module for Network Intrusion Detection System
Uses scapy for packet sniffing and feature extraction
"""

import time
import threading
import logging
from datetime import datetime
from typing import Dict, List, Callable, Any, Optional
import socket
import struct
import psutil
from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.layers.inet import Ether
import queue
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PacketSniffer:
    """Real-time network packet sniffer with feature extraction"""
    
    def __init__(self, interface: str = None, config=None):
        self.interface = interface or self._get_default_interface()
        self.config = config
        self.is_running = False
        self.capture_thread = None
        self.packet_queue = queue.Queue(maxsize=1000)
        self.packet_callback = None
        self.statistics = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'dropped_packets': 0,
            'start_time': None
        }
        
        # Connection tracking for feature engineering
        self.connections = {}
        self.connection_timeout = 300  # 5 minutes
        
        # Rate limiting
        self.max_packets_per_second = 1000
        self.last_packet_time = 0
        self.packet_count_this_second = 0
        
    def _get_default_interface(self) -> str:
        """Get the default network interface"""
        try:
            # Get network interfaces
            interfaces = psutil.net_if_addrs()
            
            # Prefer ethernet interfaces first
            for interface_name in interfaces:
                if 'eth' in interface_name.lower() or 'en' in interface_name.lower():
                    return interface_name
            
            # Fall back to any available interface except loopback
            for interface_name in interfaces:
                if interface_name != 'lo' and not interface_name.startswith('lo'):
                    return interface_name
            
            return 'any'  # Capture on all interfaces
            
        except Exception as e:
            logger.warning(f"Could not determine default interface: {str(e)}")
            return 'any'
    
    def start_capture(self, packet_callback: Callable[[Dict], None] = None,
                     filter_expression: str = None, count: int = 0):
        """
        Start packet capture
        
        Args:
            packet_callback: Function to call for each captured packet
            filter_expression: BPF filter expression
            count: Number of packets to capture (0 = infinite)
        """
        if self.is_running:
            logger.warning("Packet capture is already running")
            return
        
        self.packet_callback = packet_callback
        self.is_running = True
        self.statistics['start_time'] = datetime.now()
        
        logger.info(f"Starting packet capture on interface: {self.interface}")
        if filter_expression:
            logger.info(f"Using filter: {filter_expression}")
        
        # Start capture in separate thread
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            args=(filter_expression, count),
            daemon=True
        )
        self.capture_thread.start()
    
    def stop_capture(self):
        """Stop packet capture"""
        if not self.is_running:
            logger.warning("Packet capture is not running")
            return
        
        logger.info("Stopping packet capture...")
        self.is_running = False
        
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5)
        
        self._log_statistics()
    
    def _capture_packets(self, filter_expression: str, count: int):
        """Internal method to capture packets using scapy"""
        try:
            sniff(
                iface=self.interface if self.interface != 'any' else None,
                prn=self._process_packet,
                filter=filter_expression,
                count=count,
                stop_filter=lambda x: not self.is_running,
                store=False  # Don't store packets in memory
            )
        except Exception as e:
            logger.error(f"Error during packet capture: {str(e)}")
        finally:
            self.is_running = False
    
    def _process_packet(self, packet):
        """Process captured packet and extract features"""
        try:
            # Rate limiting
            current_time = time.time()
            if int(current_time) == int(self.last_packet_time):
                self.packet_count_this_second += 1
                if self.packet_count_this_second > self.max_packets_per_second:
                    self.statistics['dropped_packets'] += 1
                    return
            else:
                self.packet_count_this_second = 1
                self.last_packet_time = current_time
            
            # Extract packet features
            packet_info = self._extract_packet_features(packet)
            
            if packet_info:
                self.statistics['total_packets'] += 1
                
                # Update protocol statistics
                protocol = packet_info.get('protocol', '').lower()
                if protocol == 'tcp':
                    self.statistics['tcp_packets'] += 1
                elif protocol == 'udp':
                    self.statistics['udp_packets'] += 1
                elif protocol == 'icmp':
                    self.statistics['icmp_packets'] += 1
                
                # Add to queue for processing
                try:
                    self.packet_queue.put_nowait(packet_info)
                except queue.Full:
                    self.statistics['dropped_packets'] += 1
                    logger.warning("Packet queue is full, dropping packet")
                
                # Call callback if provided
                if self.packet_callback:
                    try:
                        self.packet_callback(packet_info)
                    except Exception as e:
                        logger.error(f"Error in packet callback: {str(e)}")
        
        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")
    
    def _extract_packet_features(self, packet) -> Optional[Dict[str, Any]]:
        """Extract features from packet for ML model"""
        try:
            if not packet.haslayer(IP):
                return None
            
            ip_layer = packet[IP]
            
            # Basic packet information
            packet_info = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'protocol': self._get_protocol_name(ip_layer.proto),
                'packet_size': len(packet),
                'ttl': ip_layer.ttl,
                'flags': ip_layer.flags
            }
            
            # Protocol-specific features
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_info.update({
                    'src_port': tcp_layer.sport,
                    'dst_port': tcp_layer.dport,
                    'tcp_flags': tcp_layer.flags,
                    'window_size': tcp_layer.window,
                    'seq_num': tcp_layer.seq,
                    'ack_num': tcp_layer.ack,
                    'service': self._identify_service(tcp_layer.dport)
                })
                
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                packet_info.update({
                    'src_port': udp_layer.sport,
                    'dst_port': udp_layer.dport,
                    'service': self._identify_service(udp_layer.dport)
                })
            
            elif packet.haslayer(ICMP):
                icmp_layer = packet[ICMP]
                packet_info.update({
                    'icmp_type': icmp_layer.type,
                    'icmp_code': icmp_layer.code,
                    'service': 'icmp'
                })
            
            # Connection-based features
            connection_features = self._extract_connection_features(packet_info)
            packet_info.update(connection_features)
            
            # Map to NSL-KDD feature format
            nsl_features = self._map_to_nsl_features(packet_info)
            
            return nsl_features
            
        except Exception as e:
            logger.error(f"Error extracting packet features: {str(e)}")
            return None
    
    def _get_protocol_name(self, proto_num: int) -> str:
        """Convert protocol number to name"""
        protocol_map = {1: 'icmp', 6: 'tcp', 17: 'udp'}
        return protocol_map.get(proto_num, f'proto_{proto_num}')
    
    def _identify_service(self, port: int) -> str:
        """Identify service based on port number"""
        service_map = {
            20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet',
            25: 'smtp', 53: 'dns', 80: 'http', 110: 'pop3',
            143: 'imap', 443: 'https', 993: 'imaps', 995: 'pop3s',
            1433: 'mssql', 3306: 'mysql', 5432: 'postgresql'
        }
        return service_map.get(port, 'other')
    
    def _extract_connection_features(self, packet_info: Dict) -> Dict:
        """Extract connection-based features for NSL-KDD format"""
        connection_key = f"{packet_info['src_ip']}:{packet_info.get('src_port', 0)}-{packet_info['dst_ip']}:{packet_info.get('dst_port', 0)}"
        current_time = time.time()
        
        # Clean old connections
        self._cleanup_old_connections(current_time)
        
        # Get or create connection info
        if connection_key not in self.connections:
            self.connections[connection_key] = {
                'start_time': current_time,
                'packet_count': 0,
                'bytes_sent': 0,
                'bytes_received': 0,
                'last_activity': current_time
            }
        
        conn = self.connections[connection_key]
        conn['packet_count'] += 1
        conn['bytes_sent'] += packet_info.get('packet_size', 0)
        conn['last_activity'] = current_time
        
        # Calculate connection features
        duration = current_time - conn['start_time']
        
        return {
            'duration': int(duration),
            'src_bytes': conn['bytes_sent'],
            'dst_bytes': conn['bytes_received'],
            'count': conn['packet_count']
        }
    
    def _cleanup_old_connections(self, current_time: float):
        """Remove old connections to prevent memory leak"""
        to_remove = []
        for key, conn in self.connections.items():
            if current_time - conn['last_activity'] > self.connection_timeout:
                to_remove.append(key)
        
        for key in to_remove:
            del self.connections[key]
    
    def _map_to_nsl_features(self, packet_info: Dict) -> Dict:
        """Map packet information to NSL-KDD feature format"""
        # Map TCP flags to NSL-KDD flag format
        tcp_flags = packet_info.get('tcp_flags', 0)
        flag_mapping = {
            0x02: 'S0',   # SYN
            0x12: 'SF',   # SYN-ACK
            0x18: 'SF',   # PSH-ACK
            0x04: 'REJ',  # RST
            0x14: 'RSTR'  # RST-ACK
        }
        flag = flag_mapping.get(tcp_flags, 'SF')
        
        # Create NSL-KDD compatible feature dict
        features = {
            'duration': packet_info.get('duration', 0),
            'protocol_type': packet_info.get('protocol', 'tcp'),
            'service': packet_info.get('service', 'http'),
            'flag': flag,
            'src_bytes': packet_info.get('src_bytes', 0),
            'dst_bytes': packet_info.get('dst_bytes', 0),
            'land': 1 if packet_info.get('src_ip') == packet_info.get('dst_ip') else 0,
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': 1,
            'num_compromised': 0,
            'root_shell': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 0,
            'count': packet_info.get('count', 1),
            'srv_count': 1,
            'serror_rate': 0.0,
            'srv_serror_rate': 0.0,
            'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0,
            'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0,
            'srv_diff_host_rate': 0.0,
            'dst_host_count': 1,
            'dst_host_srv_count': 1,
            'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0.0,
            'dst_host_same_src_port_rate': 0.0,
            'dst_host_srv_diff_host_rate': 0.0,
            'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0,
            'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0
        }
        
        # Add raw packet info for logging
        features['_packet_info'] = {
            'timestamp': packet_info.get('timestamp'),
            'src_ip': packet_info.get('src_ip'),
            'dst_ip': packet_info.get('dst_ip'),
            'src_port': packet_info.get('src_port'),
            'dst_port': packet_info.get('dst_port'),
            'packet_size': packet_info.get('packet_size')
        }
        
        return features
    
    def get_packet_from_queue(self, timeout: float = 1.0) -> Optional[Dict]:
        """Get packet from processing queue"""
        try:
            return self.packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None
    
    def get_statistics(self) -> Dict:
        """Get capture statistics"""
        stats = self.statistics.copy()
        if stats['start_time']:
            runtime = datetime.now() - stats['start_time']
            stats['runtime_seconds'] = runtime.total_seconds()
            stats['packets_per_second'] = stats['total_packets'] / max(1, stats['runtime_seconds'])
        
        return stats
    
    def _log_statistics(self):
        """Log capture statistics"""
        stats = self.get_statistics()
        logger.info("Packet Capture Statistics:")
        logger.info(f"  Total packets: {stats['total_packets']}")
        logger.info(f"  TCP packets: {stats['tcp_packets']}")
        logger.info(f"  UDP packets: {stats['udp_packets']}")
        logger.info(f"  ICMP packets: {stats['icmp_packets']}")
        logger.info(f"  Dropped packets: {stats['dropped_packets']}")
        if 'packets_per_second' in stats:
            logger.info(f"  Average rate: {stats['packets_per_second']:.2f} packets/sec")

class SimulatedPacketGenerator:
    """Generate simulated network packets for testing when real capture isn't available"""
    
    def __init__(self):
        self.is_running = False
        self.generation_thread = None
        
    def start_generation(self, packet_callback: Callable[[Dict], None],
                        packets_per_second: int = 10, duration: int = 60):
        """
        Start generating simulated packets
        
        Args:
            packet_callback: Function to call for each generated packet
            packets_per_second: Rate of packet generation
            duration: Duration in seconds (0 = infinite)
        """
        if self.is_running:
            logger.warning("Packet generation is already running")
            return
        
        self.is_running = True
        logger.info(f"Starting simulated packet generation at {packets_per_second} packets/sec")
        
        self.generation_thread = threading.Thread(
            target=self._generate_packets,
            args=(packet_callback, packets_per_second, duration),
            daemon=True
        )
        self.generation_thread.start()
    
    def stop_generation(self):
        """Stop packet generation"""
        if not self.is_running:
            return
        
        logger.info("Stopping packet generation...")
        self.is_running = False
        
        if self.generation_thread and self.generation_thread.is_alive():
            self.generation_thread.join(timeout=5)
    
    def _generate_packets(self, callback: Callable, pps: int, duration: int):
        """Generate simulated packets"""
        import random
        import ipaddress
        
        start_time = time.time()
        packet_interval = 1.0 / pps
        
        try:
            while self.is_running:
                if duration > 0 and (time.time() - start_time) > duration:
                    break
                
                # Generate random packet
                packet_info = self._create_random_packet()
                
                try:
                    callback(packet_info)
                except Exception as e:
                    logger.error(f"Error in packet callback: {str(e)}")
                
                time.sleep(packet_interval)
                
        except Exception as e:
            logger.error(f"Error generating packets: {str(e)}")
        finally:
            self.is_running = False
    
    def _create_random_packet(self) -> Dict:
        """Create a random packet for simulation"""
        import random
        
        protocols = ['tcp', 'udp', 'icmp']
        services = ['http', 'https', 'ftp', 'ssh', 'smtp', 'dns']
        flags = ['SF', 'S0', 'REJ', 'RSTR']
        
        # Generate random IPs
        src_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
        dst_ip = f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}"
        
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'duration': random.randint(0, 100),
            'protocol_type': random.choice(protocols),
            'service': random.choice(services),
            'flag': random.choice(flags),
            'src_bytes': random.randint(0, 10000),
            'dst_bytes': random.randint(0, 10000),
            'land': random.choice([0, 1]) if random.random() < 0.01 else 0,
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': random.choice([0, 1]),
            'num_compromised': 0,
            'root_shell': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 0,
            'count': random.randint(1, 10),
            'srv_count': random.randint(1, 5),
            'serror_rate': random.uniform(0, 0.1),
            'srv_serror_rate': random.uniform(0, 0.1),
            'rerror_rate': random.uniform(0, 0.1),
            'srv_rerror_rate': random.uniform(0, 0.1),
            'same_srv_rate': random.uniform(0.5, 1.0),
            'diff_srv_rate': random.uniform(0, 0.5),
            'srv_diff_host_rate': random.uniform(0, 0.3),
            'dst_host_count': random.randint(1, 100),
            'dst_host_srv_count': random.randint(1, 50),
            'dst_host_same_srv_rate': random.uniform(0.5, 1.0),
            'dst_host_diff_srv_rate': random.uniform(0, 0.5),
            'dst_host_same_src_port_rate': random.uniform(0, 0.3),
            'dst_host_srv_diff_host_rate': random.uniform(0, 0.3),
            'dst_host_serror_rate': random.uniform(0, 0.1),
            'dst_host_srv_serror_rate': random.uniform(0, 0.1),
            'dst_host_rerror_rate': random.uniform(0, 0.1),
            'dst_host_srv_rerror_rate': random.uniform(0, 0.1),
            '_packet_info': {
                'timestamp': datetime.now().isoformat(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': random.randint(1024, 65535),
                'dst_port': random.randint(1, 1023),
                'packet_size': random.randint(64, 1500)
            }
        }
        
        return packet_info

def main():
    """Main function for testing packet capture"""
    
    def packet_handler(packet_info):
        """Handle captured packets"""
        print(f"Captured packet: {packet_info['_packet_info']['src_ip']} -> {packet_info['_packet_info']['dst_ip']} "
              f"({packet_info['protocol_type']}) Size: {packet_info['_packet_info']['packet_size']}")
    
    # Try real packet capture first
    try:
        sniffer = PacketSniffer()
        print(f"Starting real packet capture on interface: {sniffer.interface}")
        sniffer.start_capture(packet_callback=packet_handler, count=10)
        
        # Wait for capture to complete
        while sniffer.is_running:
            time.sleep(1)
        
        print("Real packet capture completed")
        
    except Exception as e:
        print(f"Real packet capture failed: {str(e)}")
        print("Falling back to simulated packet generation...")
        
        # Fall back to simulated packets
        generator = SimulatedPacketGenerator()
        generator.start_generation(packet_callback=packet_handler, packets_per_second=5, duration=10)
        
        # Wait for generation to complete
        while generator.is_running:
            time.sleep(1)
        
        print("Simulated packet generation completed")

if __name__ == "__main__":
    main()