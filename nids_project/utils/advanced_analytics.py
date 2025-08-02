"""
Advanced Analytics module for Network Intrusion Detection System
Provides threat intelligence, behavioral analysis, and risk scoring capabilities
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import networkx as nx
from collections import defaultdict, deque
import json
import requests
import hashlib
import logging
from dataclasses import dataclass
from sklearn.cluster import DBSCAN, IsolationForest
from sklearn.preprocessing import StandardScaler
import sqlite3

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ThreatIntelligence:
    """Threat intelligence data structure"""
    ip_address: str
    threat_type: str
    confidence: float
    source: str
    first_seen: datetime
    last_seen: datetime
    description: str
    tags: List[str]

@dataclass
class BehavioralProfile:
    """Behavioral profile for entities"""
    entity_id: str
    entity_type: str  # 'ip', 'user', 'device'
    baseline_metrics: Dict[str, float]
    anomaly_score: float
    risk_level: str
    last_updated: datetime
    activity_patterns: Dict[str, List[float]]

@dataclass
class RiskAssessment:
    """Risk assessment result"""
    entity_id: str
    risk_score: float
    risk_level: str
    contributing_factors: List[str]
    recommendations: List[str]
    timestamp: datetime

class ThreatIntelligenceEngine:
    """Threat intelligence integration and management"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.threat_feeds = {
            'malware_domains': 'https://malware-domains.org/txt',
            'abuse_ch': 'https://threatfox-api.abuse.ch/api/v1/',
            'alienvault': 'https://otx.alienvault.com/api/v1/',
        }
        self.local_intelligence = {}
        self.cache_duration = timedelta(hours=6)
        
    def fetch_threat_intelligence(self, ip_address: str) -> Optional[ThreatIntelligence]:
        """Fetch threat intelligence for IP address"""
        try:
            # Check local cache first
            if ip_address in self.local_intelligence:
                intel = self.local_intelligence[ip_address]
                if datetime.now() - intel.last_seen < self.cache_duration:
                    return intel
            
            # Fetch from external sources
            threat_data = self._query_threat_feeds(ip_address)
            
            if threat_data:
                intel = ThreatIntelligence(
                    ip_address=ip_address,
                    threat_type=threat_data.get('type', 'unknown'),
                    confidence=threat_data.get('confidence', 0.5),
                    source=threat_data.get('source', 'external'),
                    first_seen=datetime.now(),
                    last_seen=datetime.now(),
                    description=threat_data.get('description', ''),
                    tags=threat_data.get('tags', [])
                )
                
                # Cache locally
                self.local_intelligence[ip_address] = intel
                return intel
                
        except Exception as e:
            logger.error(f"Error fetching threat intelligence for {ip_address}: {str(e)}")
        
        return None
    
    def _query_threat_feeds(self, ip_address: str) -> Optional[Dict]:
        """Query external threat intelligence feeds"""
        try:
            # Simulate threat intelligence lookup
            # In production, integrate with real threat feeds
            
            # Check if IP is in known malicious ranges
            malicious_ranges = [
                '192.168.100.',  # Simulated malicious range
                '10.0.0.',       # Another simulated range
        ]
            
            for malicious_range in malicious_ranges:
                if ip_address.startswith(malicious_range):
                    return {
                        'type': 'malware_c2',
                        'confidence': 0.8,
                        'source': 'threat_feed',
                        'description': f'IP {ip_address} associated with malware C2 infrastructure',
                        'tags': ['malware', 'c2', 'botnet']
                    }
            
            return None
            
        except Exception as e:
            logger.error(f"Error querying threat feeds: {str(e)}")
            return None
    
    def add_local_intelligence(self, intel: ThreatIntelligence):
        """Add threat intelligence to local database"""
        self.local_intelligence[intel.ip_address] = intel
        logger.info(f"Added threat intelligence for {intel.ip_address}")
    
    def get_threat_summary(self) -> Dict[str, int]:
        """Get summary of threat intelligence"""
        summary = defaultdict(int)
        
        for intel in self.local_intelligence.values():
            if datetime.now() - intel.last_seen < self.cache_duration:
                summary[intel.threat_type] += 1
        
        return dict(summary)

class BehavioralAnalyzer:
    """Behavioral analysis for anomaly detection"""
    
    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.profiles = {}
        self.activity_windows = defaultdict(lambda: deque(maxlen=window_size))
        self.baseline_calculator = StandardScaler()
        
    def update_activity(self, entity_id: str, activity_metrics: Dict[str, float]):
        """Update activity metrics for an entity"""
        self.activity_windows[entity_id].append({
            'timestamp': datetime.now(),
            'metrics': activity_metrics
        })
        
        # Update profile if we have enough data
        if len(self.activity_windows[entity_id]) >= 10:
            self._update_behavioral_profile(entity_id)
    
    def _update_behavioral_profile(self, entity_id: str):
        """Update behavioral profile for entity"""
        activities = self.activity_windows[entity_id]
        
        # Extract metrics for analysis
        metric_names = set()
        for activity in activities:
            metric_names.update(activity['metrics'].keys())
        
        # Create feature matrix
        feature_matrix = []
        for activity in activities:
            features = [activity['metrics'].get(metric, 0) for metric in metric_names]
            feature_matrix.append(features)
        
        feature_matrix = np.array(feature_matrix)
        
        # Calculate baseline statistics
        baseline_metrics = {
            metric: {
                'mean': np.mean(feature_matrix[:, i]),
                'std': np.std(feature_matrix[:, i]),
                'min': np.min(feature_matrix[:, i]),
                'max': np.max(feature_matrix[:, i])
            }
            for i, metric in enumerate(metric_names)
        }
        
        # Detect anomalies using Isolation Forest
        if len(feature_matrix) >= 20:
            isolation_forest = IsolationForest(contamination=0.1, random_state=42)
            anomaly_scores = isolation_forest.fit_predict(feature_matrix)
            anomaly_score = np.mean(anomaly_scores == -1)  # Proportion of anomalies
        else:
            anomaly_score = 0.0
        
        # Determine risk level
        if anomaly_score > 0.3:
            risk_level = 'high'
        elif anomaly_score > 0.1:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        # Calculate activity patterns (hourly aggregation)
        hourly_patterns = defaultdict(list)
        for activity in activities:
            hour = activity['timestamp'].hour
            for metric, value in activity['metrics'].items():
                hourly_patterns[f"{metric}_hour_{hour}"].append(value)
        
        # Average patterns
        activity_patterns = {
            pattern: np.mean(values) if values else 0.0
            for pattern, values in hourly_patterns.items()
        }
        
        # Create or update profile
        profile = BehavioralProfile(
            entity_id=entity_id,
            entity_type=self._determine_entity_type(entity_id),
            baseline_metrics=baseline_metrics,
            anomaly_score=anomaly_score,
            risk_level=risk_level,
            last_updated=datetime.now(),
            activity_patterns=activity_patterns
        )
        
        self.profiles[entity_id] = profile
        logger.info(f"Updated behavioral profile for {entity_id} (risk: {risk_level})")
    
    def _determine_entity_type(self, entity_id: str) -> str:
        """Determine entity type from ID"""
        if '.' in entity_id and len(entity_id.split('.')) == 4:
            return 'ip'
        elif '@' in entity_id:
            return 'user'
        else:
            return 'device'
    
    def get_behavioral_profile(self, entity_id: str) -> Optional[BehavioralProfile]:
        """Get behavioral profile for entity"""
        return self.profiles.get(entity_id)
    
    def detect_behavioral_anomalies(self, threshold: float = 0.2) -> List[BehavioralProfile]:
        """Detect entities with behavioral anomalies"""
        anomalous_profiles = []
        
        for profile in self.profiles.values():
            if profile.anomaly_score > threshold:
                anomalous_profiles.append(profile)
        
        return sorted(anomalous_profiles, key=lambda p: p.anomaly_score, reverse=True)

class RiskScorer:
    """Advanced risk scoring engine"""
    
    def __init__(self, threat_intel_engine: ThreatIntelligenceEngine, 
                 behavioral_analyzer: BehavioralAnalyzer):
        self.threat_intel = threat_intel_engine
        self.behavioral_analyzer = behavioral_analyzer
        
        # Risk factor weights
        self.risk_weights = {
            'threat_intelligence': 0.4,
            'behavioral_anomaly': 0.3,
            'network_context': 0.2,
            'temporal_factors': 0.1
        }
    
    def calculate_risk_score(self, entity_id: str, context: Dict = None) -> RiskAssessment:
        """Calculate comprehensive risk score for entity"""
        context = context or {}
        
        # Initialize risk components
        risk_components = {
            'threat_intelligence': 0.0,
            'behavioral_anomaly': 0.0,
            'network_context': 0.0,
            'temporal_factors': 0.0
        }
        
        contributing_factors = []
        recommendations = []
        
        # 1. Threat Intelligence Score
        if self._is_ip_address(entity_id):
            threat_intel = self.threat_intel.fetch_threat_intelligence(entity_id)
            if threat_intel:
                risk_components['threat_intelligence'] = threat_intel.confidence
                contributing_factors.append(f"Known threat: {threat_intel.threat_type}")
                recommendations.append("Block or monitor this IP address closely")
        
        # 2. Behavioral Anomaly Score
        behavioral_profile = self.behavioral_analyzer.get_behavioral_profile(entity_id)
        if behavioral_profile:
            risk_components['behavioral_anomaly'] = behavioral_profile.anomaly_score
            if behavioral_profile.anomaly_score > 0.2:
                contributing_factors.append("Anomalous behavioral patterns detected")
                recommendations.append("Investigate unusual activity patterns")
        
        # 3. Network Context Score
        network_risk = self._calculate_network_context_risk(entity_id, context)
        risk_components['network_context'] = network_risk
        if network_risk > 0.3:
            contributing_factors.append("Suspicious network context")
            recommendations.append("Review network connections and protocols")
        
        # 4. Temporal Factors Score
        temporal_risk = self._calculate_temporal_risk(entity_id, context)
        risk_components['temporal_factors'] = temporal_risk
        if temporal_risk > 0.4:
            contributing_factors.append("Activity during unusual hours")
            recommendations.append("Review activity timing patterns")
        
        # Calculate weighted risk score
        risk_score = sum(
            component_score * self.risk_weights[component]
            for component, component_score in risk_components.items()
        )
        
        # Determine risk level
        if risk_score >= 0.7:
            risk_level = 'critical'
        elif risk_score >= 0.5:
            risk_level = 'high'
        elif risk_score >= 0.3:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        # Add default recommendations based on risk level
        if risk_level in ['critical', 'high']:
            recommendations.extend([
                "Immediate investigation required",
                "Consider blocking or isolating entity"
            ])
        elif risk_level == 'medium':
            recommendations.append("Enhanced monitoring recommended")
        
        return RiskAssessment(
            entity_id=entity_id,
            risk_score=risk_score,
            risk_level=risk_level,
            contributing_factors=contributing_factors,
            recommendations=list(set(recommendations)),  # Remove duplicates
            timestamp=datetime.now()
        )
    
    def _is_ip_address(self, entity_id: str) -> bool:
        """Check if entity ID is an IP address"""
        parts = entity_id.split('.')
        if len(parts) != 4:
            return False
        
        try:
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            return True
        except ValueError:
            return False
    
    def _calculate_network_context_risk(self, entity_id: str, context: Dict) -> float:
        """Calculate risk based on network context"""
        risk_factors = []
        
        # Check for suspicious ports
        suspicious_ports = [22, 23, 1433, 3389, 5432]  # SSH, Telnet, MSSQL, RDP, PostgreSQL
        if 'destination_port' in context:
            if context['destination_port'] in suspicious_ports:
                risk_factors.append(0.3)
        
        # Check for unusual protocols
        unusual_protocols = ['icmp', 'igmp']
        if 'protocol' in context:
            if context['protocol'].lower() in unusual_protocols:
                risk_factors.append(0.2)
        
        # Check for large data transfers
        if 'bytes_transferred' in context:
            if context['bytes_transferred'] > 1000000:  # > 1MB
                risk_factors.append(0.4)
        
        # Check for connection frequency
        if 'connection_count' in context:
            if context['connection_count'] > 100:
                risk_factors.append(0.3)
        
        return min(sum(risk_factors), 1.0)
    
    def _calculate_temporal_risk(self, entity_id: str, context: Dict) -> float:
        """Calculate risk based on temporal factors"""
        current_hour = datetime.now().hour
        
        # Higher risk during off-hours (22:00 - 06:00)
        if current_hour >= 22 or current_hour <= 6:
            time_risk = 0.3
        else:
            time_risk = 0.0
        
        # Check for weekend activity if unusual for this entity
        if datetime.now().weekday() >= 5:  # Saturday or Sunday
            time_risk += 0.2
        
        # Check activity frequency
        if 'activity_frequency' in context:
            # Very high frequency might indicate automated/malicious activity
            freq = context['activity_frequency']
            if freq > 1000:  # More than 1000 activities per hour
                time_risk += 0.4
            elif freq > 100:
                time_risk += 0.2
        
        return min(time_risk, 1.0)

class NetworkTopologyAnalyzer:
    """Network topology analysis for advanced threat detection"""
    
    def __init__(self):
        self.network_graph = nx.DiGraph()
        self.communication_patterns = defaultdict(int)
        self.suspicious_subgraphs = []
    
    def add_communication(self, source_ip: str, dest_ip: str, 
                         protocol: str, timestamp: datetime, **kwargs):
        """Add communication to network graph"""
        # Add nodes
        self.network_graph.add_node(source_ip, type='ip')
        self.network_graph.add_node(dest_ip, type='ip')
        
        # Add or update edge
        if self.network_graph.has_edge(source_ip, dest_ip):
            # Update existing edge
            edge_data = self.network_graph[source_ip][dest_ip]
            edge_data['count'] = edge_data.get('count', 0) + 1
            edge_data['last_seen'] = timestamp
            edge_data['protocols'].add(protocol)
        else:
            # Add new edge
            self.network_graph.add_edge(
                source_ip, dest_ip,
                count=1,
                first_seen=timestamp,
                last_seen=timestamp,
                protocols={protocol},
                **kwargs
            )
        
        # Update communication patterns
        pattern_key = f"{source_ip}->{dest_ip}:{protocol}"
        self.communication_patterns[pattern_key] += 1
    
    def detect_suspicious_patterns(self) -> List[Dict]:
        """Detect suspicious network patterns"""
        suspicious_patterns = []
        
        # 1. Detect potential botnets (nodes with many outgoing connections)
        for node in self.network_graph.nodes():
            out_degree = self.network_graph.out_degree(node)
            if out_degree > 50:  # Arbitrary threshold
                suspicious_patterns.append({
                    'type': 'potential_botnet_member',
                    'node': node,
                    'out_degree': out_degree,
                    'risk_score': min(out_degree / 100.0, 1.0)
                })
        
        # 2. Detect scanning behavior (many connections to different ports)
        port_scanners = self._detect_port_scanners()
        suspicious_patterns.extend(port_scanners)
        
        # 3. Detect beaconing behavior (regular communication patterns)
        beaconing_patterns = self._detect_beaconing()
        suspicious_patterns.extend(beaconing_patterns)
        
        return suspicious_patterns
    
    def _detect_port_scanners(self) -> List[Dict]:
        """Detect potential port scanning behavior"""
        scanners = []
        
        for source in self.network_graph.nodes():
            # Count unique destinations
            destinations = list(self.network_graph.successors(source))
            
            if len(destinations) > 20:  # Threshold for port scanning
                # Analyze connection patterns
                connection_counts = [
                    self.network_graph[source][dest]['count']
                    for dest in destinations
                ]
                
                # Port scanners typically have low connection counts per destination
                avg_connections = np.mean(connection_counts)
                if avg_connections < 5:  # Low average connections per destination
                    scanners.append({
                        'type': 'port_scanner',
                        'node': source,
                        'target_count': len(destinations),
                        'avg_connections': avg_connections,
                        'risk_score': min(len(destinations) / 50.0, 1.0)
                    })
        
        return scanners
    
    def _detect_beaconing(self) -> List[Dict]:
        """Detect beaconing behavior (regular communication)"""
        beaconing = []
        
        # Look for edges with regular, repeated communication
        for source, dest, data in self.network_graph.edges(data=True):
            if data['count'] > 100:  # High frequency communication
                # In a real implementation, you'd analyze timing patterns
                # For now, we'll use count as a proxy
                regularity_score = min(data['count'] / 500.0, 1.0)
                
                if regularity_score > 0.5:
                    beaconing.append({
                        'type': 'beaconing',
                        'source': source,
                        'destination': dest,
                        'count': data['count'],
                        'regularity_score': regularity_score,
                        'risk_score': regularity_score * 0.8  # Beaconing is moderately suspicious
                    })
        
        return beaconing
    
    def get_node_centrality(self) -> Dict[str, float]:
        """Calculate node centrality metrics"""
        try:
            # Calculate various centrality measures
            betweenness = nx.betweenness_centrality(self.network_graph)
            closeness = nx.closeness_centrality(self.network_graph)
            eigenvector = nx.eigenvector_centrality(self.network_graph, max_iter=1000)
            
            # Combine centrality measures
            combined_centrality = {}
            for node in self.network_graph.nodes():
                combined_centrality[node] = (
                    betweenness.get(node, 0) * 0.4 +
                    closeness.get(node, 0) * 0.3 +
                    eigenvector.get(node, 0) * 0.3
                )
            
            return combined_centrality
        
        except Exception as e:
            logger.error(f"Error calculating centrality: {str(e)}")
            return {}
    
    def export_graph_data(self) -> Dict:
        """Export network graph data for visualization"""
        nodes = []
        edges = []
        
        # Export nodes
        for node, data in self.network_graph.nodes(data=True):
            nodes.append({
                'id': node,
                'type': data.get('type', 'unknown'),
                'degree': self.network_graph.degree(node)
            })
        
        # Export edges
        for source, dest, data in self.network_graph.edges(data=True):
            edges.append({
                'source': source,
                'target': dest,
                'count': data.get('count', 1),
                'protocols': list(data.get('protocols', [])),
                'weight': min(data.get('count', 1) / 10.0, 5.0)  # Normalize for visualization
            })
        
        return {
            'nodes': nodes,
            'edges': edges,
            'stats': {
                'node_count': len(nodes),
                'edge_count': len(edges),
                'density': nx.density(self.network_graph)
            }
        }

def main():
    """Main function for testing advanced analytics"""
    # Initialize components
    threat_intel = ThreatIntelligenceEngine()
    behavioral_analyzer = BehavioralAnalyzer()
    risk_scorer = RiskScorer(threat_intel, behavioral_analyzer)
    topology_analyzer = NetworkTopologyAnalyzer()
    
    # Simulate some data
    test_ips = ['192.168.1.10', '192.168.100.5', '10.0.0.15']
    
    print("Testing Advanced Analytics Components")
    print("=" * 50)
    
    # Test threat intelligence
    print("\n1. Threat Intelligence:")
    for ip in test_ips:
        intel = threat_intel.fetch_threat_intelligence(ip)
        if intel:
            print(f"  {ip}: {intel.threat_type} (confidence: {intel.confidence})")
        else:
            print(f"  {ip}: No threat intelligence")
    
    # Test behavioral analysis
    print("\n2. Behavioral Analysis:")
    for ip in test_ips:
        # Simulate activity metrics
        metrics = {
            'connection_count': np.random.poisson(10),
            'bytes_transferred': np.random.exponential(1000),
            'protocol_diversity': np.random.uniform(1, 5)
        }
        behavioral_analyzer.update_activity(ip, metrics)
    
    # Test risk scoring
    print("\n3. Risk Assessment:")
    for ip in test_ips:
        risk_assessment = risk_scorer.calculate_risk_score(ip)
        print(f"  {ip}: Risk Level {risk_assessment.risk_level} (score: {risk_assessment.risk_score:.3f})")
    
    # Test network topology
    print("\n4. Network Topology Analysis:")
    # Simulate network communications
    for _ in range(100):
        source = np.random.choice(test_ips)
        dest = np.random.choice(test_ips)
        if source != dest:
            topology_analyzer.add_communication(
                source, dest, 'tcp', datetime.now()
            )
    
    suspicious_patterns = topology_analyzer.detect_suspicious_patterns()
    print(f"  Detected {len(suspicious_patterns)} suspicious patterns")
    
    print("\nAdvanced analytics testing completed!")

if __name__ == "__main__":
    main()