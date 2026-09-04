export interface Target {
  id: number; name: string; ip_address: string; port: number; description: string; environment: string;
  udp_enabled: boolean; tcp_enabled: boolean; tags: string[]; created_at: string; updated_at: string
}
export type TargetInput = Omit<Target, 'id'|'created_at'|'updated_at'>
interface ProtocolCheck { available: boolean; latency_ms: number; error?: string }
export interface DiscoveryProfile {
  target: string; checked_at: string; udp: ProtocolCheck; tcp: ProtocolCheck; recursion_enabled: boolean;
  authoritative: boolean; edns_supported: boolean; dnssec_supported: boolean; response_size: number;
  tcp_fallback: boolean; average_latency_ms: number; flags: { ra:boolean; rd:boolean; aa:boolean; tc:boolean }
}
type TestStatus='PENDING'|'RUNNING'|'COMPLETED'|'FAILED'|'CANCELLED'
export interface TestRun {
  id:number;target_id:number;scenario:string;status:TestStatus;created_at:string;started_at?:string;
  finished_at?:string;duration_seconds:number;config:Record<string,unknown>;resilience_score?:number;
  result?:Record<string,unknown>;
}
export interface CreateTestInput { target_id:number;scenario:string;config:Record<string,unknown> }

export interface ScenarioLimits { max_qps: number; max_duration_seconds: number; max_workers: number; }

export interface ScenarioMetadata {
  id: string;
  name: string;
  category: string;
  description: string;
  supported_protocols: string[];
  required_parameters: string[];
  risk_level: string;
  default_config: Record<string, unknown>;
  recommended_limits: ScenarioLimits;
}
