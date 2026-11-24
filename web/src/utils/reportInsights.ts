import type { TestRun } from '../types';

// Severity drives the colour, icon and label used across the report UI and PDF.
export type InsightSeverity = 'secure' | 'info' | 'warning' | 'critical';

export interface ReportInsight {
  // One-line verdict headline, e.g. "No DNS Cookie protection".
  title: string;
  severity: InsightSeverity;
  // What the scenario actually observed, in plain language.
  summary: string;
  // Why that result matters — the concrete risk or benefit.
  impact: string;
  // The single most useful next step for the operator.
  recommendation: string;
}

const num = (value: unknown): number => {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
};
const bool = (value: unknown): boolean => value === true || value === 'true';
const has = (value: unknown): boolean => value !== undefined && value !== null;

// severityFromScore is the fallback mapping when a scenario has no bespoke rule.
function severityFromScore(score: number): InsightSeverity {
  if (score >= 90) return 'secure';
  if (score >= 50) return 'warning';
  return 'critical';
}

// interpretReport turns a completed test's raw result map into an explanatory
// assessment. It is the single source of truth for both the on-screen report
// card and the PDF executive summary, so the two never disagree.
export function interpretReport(test: TestRun): ReportInsight {
  const score = num(test.resilience_score);
  const r = test.result ?? {};

  if (test.status === 'FAILED') {
    return {
      title: 'Execution failed',
      severity: 'critical',
      summary: 'The scenario did not run to completion, so no resilience assessment could be produced.',
      impact: 'A failed run usually means the target was unreachable, refused the connection, or dropped every probe — which can itself indicate the server is down or filtering the source.',
      recommendation: 'Confirm the target IP/port and that UDP/TCP are reachable from this host, then re-run the scenario.',
    };
  }
  if (test.status !== 'COMPLETED') {
    return {
      title: 'Awaiting results',
      severity: 'info',
      summary: 'This test has not finished executing yet.',
      impact: 'No findings are available until the orchestrator completes the run.',
      recommendation: 'Watch the live console or refresh once the status reads COMPLETED.',
    };
  }

  switch (test.scenario) {
    case 'security-audit': {
      if (score < 50) {
        return {
          title: 'Critical misconfiguration',
          severity: 'critical',
          summary: 'The audit found open recursion, version disclosure, or an unauthorized zone transfer exposure.',
          impact: 'An open resolver can be abused for cache poisoning and reflection/amplification DDoS, and a leaked zone or version aids targeted attacks.',
          recommendation: 'Restrict recursion to trusted clients, hide the version (CHAOS TXT), and disable AXFR except to secondary nameservers.',
        };
      }
      if (score < 90) {
        return {
          title: 'Hardening gaps found',
          severity: 'warning',
          summary: 'Core controls are in place but the audit surfaced information leaks or minor misconfigurations.',
          impact: 'Each leak (version banner, permissive ANY, etc.) narrows the work an attacker needs to do.',
          recommendation: 'Review the detailed findings below and close the flagged leaks.',
        };
      }
      return {
        title: 'Secure configuration',
        severity: 'secure',
        summary: 'Recursion, version disclosure and zone transfers are all handled according to best practice.',
        impact: 'The server resists the most common DNS reconnaissance and abuse vectors.',
        recommendation: 'Keep the software patched and re-audit after any configuration change.',
      };
    }

    case 'zone-transfer-audit': {
      const leaked = num(r.total_leaked_records);
      if (leaked > 0) {
        return {
          title: 'Zone transfer leak',
          severity: 'critical',
          summary: `An unauthorized AXFR succeeded and siphoned ${leaked} records from the zone.`,
          impact: 'A full zone copy hands an attacker every hostname, internal service and IP in the domain — a complete map of the attack surface.',
          recommendation: 'Disable AXFR globally and allow transfers only to explicitly listed secondary nameserver IPs.',
        };
      }
      return {
        title: 'Zone transfers refused',
        severity: 'secure',
        summary: 'The server correctly rejected the unauthorized AXFR request.',
        impact: 'The zone database is not exposed to anonymous enumeration.',
        recommendation: 'Keep AXFR restricted to secondaries and monitor for transfer attempts.',
      };
    }

    case 'amplification-audit': {
      const factor = num(r.max_amplification_factor);
      const rrl = bool(r.rrl_active);
      if (factor > 20) {
        return {
          title: `High amplification (~${factor}x)`,
          severity: 'critical',
          summary: `The server returns responses up to ~${factor}x the request size${rrl ? '' : ' with no Response Rate Limiting'}.`,
          impact: 'A large amplification factor without RRL makes this server an attractive reflector for volumetric DDoS against third parties.',
          recommendation: 'Enable Response Rate Limiting, minimize ANY responses (RFC 8482), and require DNS Cookies for UDP clients.',
        };
      }
      if (factor > 10 || !rrl) {
        return {
          title: 'Moderate amplification exposure',
          severity: 'warning',
          summary: `Amplification peaks around ~${factor}x${rrl ? ' but RRL is active' : ' and RRL was not observed'}.`,
          impact: 'Any UDP amplification plus weak rate limiting adds reflection potential.',
          recommendation: 'Turn on RRL and cap large answer types; re-test to confirm the factor drops.',
        };
      }
      return {
        title: 'Low amplification surface',
        severity: 'secure',
        summary: `Responses stay close to request size (~${factor}x) and rate limiting is in effect.`,
        impact: 'The server is a poor candidate for reflection abuse.',
        recommendation: 'Maintain RRL and ANY minimization.',
      };
    }

    case 'dns-fuzzing': {
      if (bool(r.target_crashed)) {
        return {
          title: 'Crashed under malformed input',
          severity: 'critical',
          summary: 'A post-fuzz health check failed — the server became unresponsive after a malformed packet vector.',
          impact: 'A single crafted packet can take the resolver down, a direct denial-of-service with no volume required.',
          recommendation: 'Patch/upgrade the DNS software immediately and add strict packet-parsing validation upstream.',
        };
      }
      return {
        title: 'Crash-resilient',
        severity: 'secure',
        summary: `The server stayed responsive through ${num(r.vectors_tested)} malformed-packet vectors.`,
        impact: 'Malformed-input DoS is not a viable path against this server today.',
        recommendation: 'Re-run after software updates to catch regressions.',
      };
    }

    case 'subdomain-takeover': {
      const vuln = num(r.vulnerable_count);
      if (vuln > 0) {
        return {
          title: `${vuln} dangling CNAME${vuln === 1 ? '' : 's'}`,
          severity: 'critical',
          summary: `${vuln} subdomain(s) point to decommissioned cloud resources that can be re-registered by anyone.`,
          impact: 'An attacker who claims the backend serves content from your subdomain — phishing, cookie theft and brand abuse under a trusted name.',
          recommendation: 'Remove the orphaned CNAME records or re-claim the backend resources now.',
        };
      }
      return {
        title: 'No takeover vectors',
        severity: 'secure',
        summary: `All ${num(r.subdomains_scanned)} scanned CNAMEs resolve to live backends.`,
        impact: 'No dangling delegation is available for takeover.',
        recommendation: 'Re-scan whenever cloud resources are decommissioned.',
      };
    }

    case 'rrl-threshold': {
      const active = bool(r.rate_limit_active);
      const slip = bool(r.slip_fallback_active);
      const threshold = num(r.detected_threshold_qps);
      if (!active) {
        return {
          title: 'No rate limiting',
          severity: 'warning',
          summary: 'The server answered sustained high-QPS UDP bursts without throttling.',
          impact: 'With no RRL the server can be driven as a reflector and offers no brake against query floods.',
          recommendation: 'Enable Response Rate Limiting with a SLIP value so legitimate clients fall back to TCP.',
        };
      }
      return {
        title: slip ? 'RRL + SLIP active' : 'RRL active (strict drop)',
        severity: 'secure',
        summary: `Rate limiting engaged around ${threshold} QPS${slip ? ' with TC=1 SLIP fallback for genuine resolvers' : ' using strict UDP drops'}.`,
        impact: 'Reflection and flood abuse are throttled.',
        recommendation: slip ? 'Posture is strong; keep monitoring thresholds.' : 'Consider a SLIP value so real clients can retry over TCP.',
      };
    }

    case 'dns-tunneling': {
      const delivered = num(r.delivered_chunks);
      if (delivered > 0) {
        return {
          title: 'Covert tunnel passed',
          severity: 'critical',
          summary: `${delivered} high-entropy payload chunks were carried through DNS queries unblocked.`,
          impact: 'DNS can be used as a covert channel for data exfiltration and C2 that bypasses conventional egress controls.',
          recommendation: 'Add DNS query length/entropy inspection and alert on anomalous subdomain patterns at the resolver or firewall.',
        };
      }
      return {
        title: 'Tunneling blocked',
        severity: 'secure',
        summary: 'High-entropy covert queries were refused or dropped before completing.',
        impact: 'The covert-channel exfiltration path is not open here.',
        recommendation: 'Keep entropy/length inspection enabled.',
      };
    }

    case 'ecs-manipulation': {
      const ecs = bool(r.ecs_supported);
      return {
        title: ecs ? 'ECS echoed' : 'ECS stripped',
        severity: ecs ? 'info' : 'secure',
        summary: ecs
          ? 'The server processed and reflected EDNS0 Client Subnet options across regions.'
          : 'The server ignored or stripped client-subnet options.',
        impact: ecs
          ? 'ECS enables geo-aware answers but widens cache fragmentation and leaks client network prefixes to authoritatives.'
          : 'Client network prefixes are not forwarded, favouring privacy.',
        recommendation: ecs
          ? 'Confirm ECS is intentional; if not required, disable it to protect client privacy and shrink the cache.'
          : 'No action needed unless geo-routing is a requirement.',
      };
    }

    case 'dnssec-audit': {
      const dnskey = bool(r.dnskey_present);
      const rrsig = bool(r.rrsig_present);
      if (dnskey && rrsig) {
        return {
          title: 'DNSSEC signed',
          severity: 'secure',
          summary: 'Valid DNSKEY and RRSIG records were returned for the zone.',
          impact: 'Responses can be cryptographically validated, defeating most cache-poisoning attacks.',
          recommendation: 'Monitor signature expiry and key rollovers so validation never lapses.',
        };
      }
      if (dnskey) {
        return {
          title: 'Partial DNSSEC',
          severity: 'warning',
          summary: 'A DNSKEY is present but the expected signatures were incomplete.',
          impact: 'Incomplete signing can cause validation failures or leave records unprotected.',
          recommendation: 'Verify the full signing chain (DNSKEY, DS at parent, RRSIG on records).',
        };
      }
      return {
        title: 'Zone not signed',
        severity: 'warning',
        summary: 'No DNSKEY/DS records were returned — the zone is not DNSSEC-signed.',
        impact: 'Answers cannot be cryptographically validated, leaving clients exposed to cache poisoning.',
        recommendation: 'Sign the zone with DNSSEC and publish a DS record at the parent.',
      };
    }

    case 'tcp-slowloris': {
      if (r.legitimate_tcp_served === false) {
        return {
          title: 'TCP exhaustion DoS',
          severity: 'critical',
          summary: 'Legitimate TCP queries were refused while slow sockets were held open.',
          impact: 'An attacker can starve the TCP listener with a handful of idle connections, blocking large/EDNS responses and TCP-only clients.',
          recommendation: 'Set aggressive idle timeouts and a per-client TCP connection cap, and front the server with a connection-aware proxy.',
        };
      }
      return {
        title: 'TCP resilient',
        severity: 'secure',
        summary: `The server kept serving legitimate TCP queries (${num(r.connections_established)}/${num(r.connections_requested)} slow sockets held).`,
        impact: 'Slow-connection exhaustion is not a viable DoS here.',
        recommendation: 'Keep idle timeouts and connection caps in place.',
      };
    }

    case 'any-refuse-audit': {
      if (bool(r.any_refused) || bool(r.rfc8482_hinfo)) {
        return {
          title: 'ANY minimized (RFC 8482)',
          severity: 'secure',
          summary: bool(r.any_refused)
            ? `The server refuses QTYPE=ANY (${String(r.any_rcode ?? 'REFUSED')}).`
            : 'The server returns a synthetic HINFO instead of expanding ANY.',
          impact: 'Minimizing ANY removes a major amplification lever for reflection DDoS.',
          recommendation: 'No change needed; keep ANY minimization enabled.',
        };
      }
      const factor = num(r.amplification_factor);
      if (score < 60 || factor >= 3) {
        return {
          title: `ANY amplification (~${factor}x)`,
          severity: 'critical',
          summary: `The server fully expands ANY into ${num(r.any_answer_count)} RRsets (~${factor}x the baseline response).`,
          impact: 'Large ANY responses make the server a strong amplification reflector for volumetric DDoS.',
          recommendation: 'Enable RFC 8482 ANY minimization (REFUSE or synthesize HINFO) and turn on RRL.',
        };
      }
      return {
        title: 'ANY answered, low amplification',
        severity: 'warning',
        summary: `ANY is answered but amplification is modest (~${factor}x).`,
        impact: 'Some reflection potential remains.',
        recommendation: 'Consider minimizing ANY responses to remove the remaining lever.',
      };
    }

    case 'dns-cookie-audit': {
      if (bool(r.server_cookie_present) || bool(r.bad_cookie_enforced)) {
        return {
          title: 'DNS Cookies supported',
          severity: 'secure',
          summary: bool(r.bad_cookie_enforced)
            ? 'The server enforces DNS Cookies (BADCOOKIE challenge with a server cookie).'
            : 'The server returns a server cookie (RFC 7873).',
          impact: 'DNS Cookies defeat most off-path spoofing and sharply reduce the value of the server as an amplification reflector.',
          recommendation: 'No change needed; keep cookies enabled.',
        };
      }
      return {
        title: 'No DNS Cookie protection',
        severity: 'warning',
        summary: 'The server ignored the EDNS0 COOKIE option and issued no server cookie.',
        impact: 'Without cookies the server is more susceptible to off-path spoofing and is easier to abuse for reflection/amplification.',
        recommendation: 'Enable DNS Cookies (RFC 7873) on the resolver/authoritative software.',
      };
    }

    case 'cache-snooping': {
      const cached = num(r.cached_count);
      const answered = num(r.probes_answered);
      if (cached > 0) {
        return {
          title: 'Cache snooping exposed',
          severity: 'warning',
          summary: `${cached} of ${answered} probe names were served from cache to a non-recursive (RD=0) query.`,
          impact: 'Anyone can enumerate which sites this resolver’s clients visit — an information-disclosure and privacy leak, and a sign of an openly reachable resolver.',
          recommendation: 'Restrict the resolver to trusted clients and/or disable serving cached answers to RD=0 queries from untrusted sources.',
        };
      }
      return {
        title: 'Not snoopable',
        severity: 'secure',
        summary: 'No probe names were served from cache to non-recursive queries.',
        impact: 'Client browsing patterns are not exposed via RD=0 snooping.',
        recommendation: 'Keep recursion limited to trusted networks.',
      };
    }

    case 'edns-tcp-fallback': {
      if (!bool(r.edns_supported)) {
        return {
          title: 'No EDNS0 support',
          severity: 'warning',
          summary: 'The server returned no EDNS0 OPT record.',
          impact: 'Legacy behaviour forces small UDP answers and fragmentation, a precondition for SAD DNS and a source of modern-feature loss (DNSSEC, cookies, large responses).',
          recommendation: 'Upgrade/enable EDNS0 on the DNS software.',
        };
      }
      if (bool(r.tcp_checked) && bool(r.truncation_observed) && !bool(r.tcp_fallback_ok)) {
        return {
          title: 'TCP fallback broken',
          severity: 'warning',
          summary: 'Responses truncate (TC=1) but the TCP fallback did not return an answer.',
          impact: 'Large responses (DNSSEC, big RRsets) may be undeliverable, causing intermittent resolution failures.',
          recommendation: 'Ensure the DNS service accepts TCP/53 and that no firewall blocks DNS over TCP.',
        };
      }
      return {
        title: 'EDNS0 compliant',
        severity: 'secure',
        summary: bool(r.tcp_checked)
          ? 'EDNS0 is supported and large-response delivery (TC=1 → TCP fallback) is healthy.'
          : 'EDNS0 is supported; TCP fallback was not verified because TCP is disabled for this target.',
        impact: 'Large and signed responses are delivered reliably.',
        recommendation: bool(r.tcp_checked) ? 'No action needed.' : 'Enable TCP on the target to fully verify large-response delivery.',
      };
    }

    case 'dns-0x20': {
      if (bool(r.case_preserved)) {
        return {
          title: '0x20 case preserved',
          severity: 'secure',
          summary: 'The server echoed the exact mixed-case query name.',
          impact: 'DNS-0x20 adds transaction entropy that makes off-path answer spoofing harder.',
          recommendation: 'No change needed.',
        };
      }
      return {
        title: 'Case normalized',
        severity: 'info',
        summary: 'The server lower-cased the query name in its echo instead of preserving it.',
        impact: 'It cannot carry DNS-0x20 anti-spoofing entropy for downstream queries, though case handling alone is not a vulnerability.',
        recommendation: 'Enable 0x20 case randomization if the software supports it; otherwise rely on DNS Cookies/DNSSEC for anti-spoofing.',
      };
    }

    case 'water-torture': {
      const nxdomain = num(r.nxdomain_count);
      const timeouts = num(r.timeouts);
      if (score <= 40) {
        return {
          title: 'Buckled under subdomain flood',
          severity: 'critical',
          summary: `A high error/drop rate was seen while flooding random subdomains (${nxdomain} NXDOMAIN, ${timeouts} timeouts).`,
          impact: 'A water-torture flood of random names can exhaust the resolver and the authoritative servers it queries, degrading or denying service for everyone.',
          recommendation: 'Add rate limiting and aggressive negative caching, and isolate recursion so random-subdomain floods cannot overwhelm upstream authoritatives.',
        };
      }
      if (score < 100) {
        return {
          title: 'Upstream pressure under flood',
          severity: 'warning',
          summary: `The server absorbed the flood but ${nxdomain} queries reached NXDOMAIN, so cache misses are chasing upstream authoritatives.`,
          impact: 'Sustained random-subdomain floods push load onto authoritative servers and can slow legitimate resolution.',
          recommendation: 'Tune negative (NXDOMAIN) caching and consider rate limiting random-subdomain query patterns.',
        };
      }
      return {
        title: 'Resisted subdomain flood',
        severity: 'secure',
        summary: 'The server stayed bounded under the random-subdomain flood with a low error rate.',
        impact: 'Water-torture flooding does not readily degrade this server.',
        recommendation: 'Keep negative caching and rate limiting in place.',
      };
    }

    case 'qps-ramp': {
      const maxQps = num(r.max_qps_reached);
      if (score >= 90) {
        return {
          title: `Sustained ${maxQps} QPS`,
          severity: 'secure',
          summary: `The server handled the full ramp, staying stable up to ${maxQps} QPS.`,
          impact: 'Capacity headroom is sufficient across the tested rate range.',
          recommendation: 'Raise the ceiling (max QPS / step) to find the true breaking point.',
        };
      }
      if (score >= 50) {
        return {
          title: `Stable to ~${maxQps} QPS`,
          severity: 'warning',
          summary: `The server became unstable above ~${maxQps} QPS before reaching the target ceiling.`,
          impact: 'Beyond this rate responses degrade or drop — the practical capacity limit under burst.',
          recommendation: 'Plan capacity below this threshold, or scale/tune the resolver before expected peaks.',
        };
      }
      return {
        title: `Low capacity (~${maxQps} QPS)`,
        severity: 'critical',
        summary: `The server degraded at a low query rate (~${maxQps} QPS).`,
        impact: 'A modest query burst is enough to degrade service, making the server easy to overwhelm.',
        recommendation: 'Investigate resource limits and rate-limiter settings; scale capacity before production load.',
      };
    }

    default: {
      // Pure performance scenarios (benchmark, query-flood, nxdomain,
      // random-subdomain) are judged on loss and latency rather than a security
      // posture. Their result maps always carry loss and p99_latency_ms.
      const loss = num(r.loss);
      const p99 = has(r.p99_latency_ms) ? num(r.p99_latency_ms) : undefined;
      if (loss > 0) {
        return {
          title: 'Packet loss under load',
          severity: 'critical',
          summary: `The server dropped queries under load (loss rate ${loss}).`,
          impact: 'Dropped UDP responses mean real clients fail to resolve during traffic spikes — effective degradation or outage.',
          recommendation: 'Investigate resource limits and rate-limiting thresholds; scale capacity or tune RRL so legitimate traffic is not dropped.',
        };
      }
      if (score < 100 && score > 0) {
        return {
          title: 'Degraded under load',
          severity: 'warning',
          summary: `The server answered every query but performance dropped under load${p99 !== undefined ? ` (p99 ${p99.toFixed(1)} ms)` : ''}.`,
          impact: 'Elevated latency slows resolution for users during peaks even without outright loss.',
          recommendation: 'Review capacity headroom and latency sources (upstream, CPU, cache size) before the next traffic spike.',
        };
      }
      return {
        title: 'Handled load cleanly',
        severity: 'secure',
        summary: `The server sustained the workload with no packet loss${p99 !== undefined ? ` and p99 latency of ${p99.toFixed(1)} ms` : ''}.`,
        impact: 'Capacity is sufficient for the tested query rate.',
        recommendation: 'Re-test at higher rates to find the real ceiling.',
      };
    }
  }
}

// Palette helpers so the modal (CSS vars) and PDF (RGB) stay in sync.
export const severityUi: Record<InsightSeverity, { label: string; color: string; bg: string; border: string }> = {
  secure: { label: 'SECURE', color: 'var(--accent-green)', bg: 'rgba(16, 185, 129, 0.08)', border: 'rgba(16, 185, 129, 0.35)' },
  info: { label: 'NOTICE', color: 'var(--accent-blue)', bg: 'rgba(59, 130, 246, 0.08)', border: 'rgba(59, 130, 246, 0.35)' },
  warning: { label: 'WARNING', color: 'var(--accent-amber)', bg: 'rgba(245, 158, 11, 0.08)', border: 'rgba(245, 158, 11, 0.35)' },
  critical: { label: 'CRITICAL', color: 'var(--accent-red)', bg: 'rgba(239, 68, 68, 0.08)', border: 'rgba(239, 68, 68, 0.4)' },
};

export const severityPdf: Record<InsightSeverity, { bg: [number, number, number]; border: [number, number, number]; title: [number, number, number]; text: [number, number, number]; label: string }> = {
  secure: { bg: [240, 253, 244], border: [34, 197, 94], title: [21, 128, 61], text: [20, 83, 45], label: 'SECURE' },
  info: { bg: [239, 246, 255], border: [59, 130, 246], title: [30, 64, 175], text: [30, 58, 138], label: 'NOTICE' },
  warning: { bg: [255, 251, 235], border: [245, 158, 11], title: [180, 83, 9], text: [146, 64, 14], label: 'WARNING' },
  critical: { bg: [254, 242, 242], border: [239, 68, 68], title: [185, 28, 28], text: [127, 29, 29], label: 'CRITICAL' },
};
