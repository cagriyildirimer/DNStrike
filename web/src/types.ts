export interface Target {
  id: number; name: string; ip_address: string; port: number; description: string; environment: string;
  udp_enabled: boolean; tcp_enabled: boolean; tags: string[]; created_at: string; updated_at: string
}
export type TargetInput = Omit<Target, 'id'|'created_at'|'updated_at'>
export interface ProtocolCheck { available: boolean; latency_ms: number; error?: string }
export interface DiscoveryProfile {
  target: string; checked_at: string; udp: ProtocolCheck; tcp: ProtocolCheck; recursion_enabled: boolean;
  authoritative: boolean; edns_supported: boolean; dnssec_supported: boolean; response_size: number;
  tcp_fallback: boolean; average_latency_ms: number; flags: { ra:boolean; rd:boolean; aa:boolean; tc:boolean }
}
export type TestStatus='PENDING'|'RUNNING'|'COMPLETED'|'FAILED'|'CANCELLED'
export interface TestRun {
  id:number;target_id:number;scenario:string;status:TestStatus;created_at:string;started_at?:string;
  finished_at?:string;duration_seconds:number;config:Record<string,unknown>;resilience_score?:number
}
export interface CreateTestInput { target_id:number;scenario:string;config:Record<string,unknown> }
export interface MetricSnapshot {
  timestamp:string;elapsed_seconds:number;current_qps:number;responses_per_second:number;total_queries:number;
  total_responses:number;timeouts:number;timeout_percent:number;errors:number;response_codes:Record<string,number>;
  min_latency_ms:number;average_latency_ms:number;max_latency_ms:number;p50_latency_ms:number;p90_latency_ms:number;
  p95_latency_ms:number;p99_latency_ms:number
}
