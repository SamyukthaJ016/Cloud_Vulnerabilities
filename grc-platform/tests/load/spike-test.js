/* global __VU */
import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';
import { randomIntBetween } from 'https://jslib.k6.io/k6-utils/1.2.0/index.js';
import { BASE_URL, ENDPOINTS, getHeaders, SCENARIOS } from './config.js';

/**
 * Spike Test
 * Tests system behavior during sudden traffic spikes
 * Simulates viral content, marketing campaigns, or DDoS scenarios
 * Run: k6 run tests/load/spike-test.js
 */

// Metrics
const errorRate = new Rate('errors');
const spikeLatency = new Trend('spike_latency');
const normalLatency = new Trend('normal_latency');
const recoveryLatency = new Trend('recovery_latency');
const requestsInSpike = new Counter('requests_during_spike');

// Track test phases
let currentPhase = 'normal';
const spikeThreshold = 100; // VUs above this considered spike

export const options = {
  scenarios: {
    spike_test: SCENARIOS.spike,
  },
  thresholds: {
    // Accept some degradation during spike
    http_req_duration: ['p(95)<10000'],  // 95% under 10s during spike
    http_req_failed: ['rate<0.20'],       // Up to 20% errors during spike
    errors: ['rate<0.25'],
    // Normal period should be fast
    normal_latency: ['p(95)<2000'],
    // Recovery should return to normal
    recovery_latency: ['p(95)<3000'],
  },
  tags: {
    testType: 'spike',
  },
};

export default function() {
  const headers = getHeaders();

  // Determine current phase based on VU count
  const vuCount = __VU;
  if (vuCount > spikeThreshold) {
    currentPhase = 'spike';
  } else if (currentPhase === 'spike') {
    currentPhase = 'recovery';
  }

  // Critical endpoints that must survive spikes
  const criticalEndpoints = [
    { url: ENDPOINTS.dashboardSummary, name: 'dashboard', weight: 3 },
    { url: ENDPOINTS.controlsList, name: 'controls', weight: 2 },
    { url: ENDPOINTS.integrationsList, name: 'integrations', weight: 2 },
    { url: ENDPOINTS.frameworksList, name: 'frameworks', weight: 1 },
    { url: ENDPOINTS.risksList, name: 'risks', weight: 1 },
  ];

  // Weighted random selection (more likely to hit high-traffic endpoints)
  const weightedEndpoints = criticalEndpoints.flatMap(e =>
    Array(e.weight).fill(e)
  );
  const endpoint = weightedEndpoints[randomIntBetween(0, weightedEndpoints.length - 1)];

  group(`Spike Test - ${currentPhase}`, () => {
    const res = http.get(`${BASE_URL}${endpoint.url}`, {
      headers,
      tags: {
        endpoint: endpoint.name,
        phase: currentPhase,
      },
    });

    const success = check(res, {
      'status is not 5xx': (r) => r.status < 500,
      'response received': (r) => r.timings.duration > 0,
    });

    errorRate.add(!success);

    // Track latency by phase
    switch (currentPhase) {
      case 'spike':
        spikeLatency.add(res.timings.duration);
        requestsInSpike.add(1);
        break;
      case 'recovery':
        recoveryLatency.add(res.timings.duration);
        break;
      default:
        normalLatency.add(res.timings.duration);
    }

    // Log significant events
    if (res.status >= 500) {
      console.log(`🔴 Server error during ${currentPhase} phase: ${res.status}`);
    }

    if (res.timings.duration > 5000) {
      console.log(`⚠️ Slow response during ${currentPhase}: ${res.timings.duration}ms`);
    }
  });

  // Think time varies by phase
  const thinkTime = currentPhase === 'spike'
    ? randomIntBetween(0.1, 0.3)  // Minimal during spike
    : randomIntBetween(0.5, 1.5); // Normal otherwise

  sleep(thinkTime);
}

export function handleSummary(data) {
  const { metrics } = data;

  const analysis = {
    testType: 'Spike Test',
    timestamp: new Date().toISOString(),

    // Overall metrics
    overall: {
      totalRequests: metrics.http_reqs?.values?.count || 0,
      failedRequests: metrics.http_req_failed?.values?.fails || 0,
      errorRate: ((metrics.errors?.values?.rate || 0) * 100).toFixed(2) + '%',
      peakVUs: metrics.vus?.values?.max || 0,
    },

    // Phase-specific latency
    phaseLatency: {
      normal: {
        avg: Math.round(metrics.normal_latency?.values?.avg || 0),
        p95: Math.round(metrics.normal_latency?.values?.['p(95)'] || 0),
      },
      spike: {
        avg: Math.round(metrics.spike_latency?.values?.avg || 0),
        p95: Math.round(metrics.spike_latency?.values?.['p(95)'] || 0),
        requestCount: metrics.requests_during_spike?.values?.count || 0,
      },
      recovery: {
        avg: Math.round(metrics.recovery_latency?.values?.avg || 0),
        p95: Math.round(metrics.recovery_latency?.values?.['p(95)'] || 0),
      },
    },

    // Spike impact analysis
    impact: analyzeImpact(metrics),

    // Recommendations
    recommendations: generateSpikeRecommendations(metrics),
  };

  return {
    'stdout': generateSpikeReport(analysis),
    'tests/load/results/spike-test-summary.json': JSON.stringify(analysis, null, 2),
  };
}

function analyzeImpact(metrics) {
  const normalAvg = metrics.normal_latency?.values?.avg || 1;
  const spikeAvg = metrics.spike_latency?.values?.avg || normalAvg;
  const recoveryAvg = metrics.recovery_latency?.values?.avg || normalAvg;

  return {
    latencyIncreaseDuringSpike: `${((spikeAvg / normalAvg - 1) * 100).toFixed(1)}%`,
    latencyAfterRecovery: `${((recoveryAvg / normalAvg - 1) * 100).toFixed(1)}%`,
    systemRecovered: recoveryAvg < spikeAvg * 0.5,
  };
}

function generateSpikeRecommendations(metrics) {
  const recommendations = [];

  const errorRate = (metrics.errors?.values?.rate || 0) * 100;
  const spikeP95 = metrics.spike_latency?.values?.['p(95)'] || 0;
  const recoveryP95 = metrics.recovery_latency?.values?.['p(95)'] || 0;
  const normalP95 = metrics.normal_latency?.values?.['p(95)'] || 0;

  if (errorRate > 10) {
    recommendations.push('High error rate during spike - implement circuit breakers');
  }

  if (spikeP95 > 5000) {
    recommendations.push('Consider auto-scaling or CDN for traffic spikes');
  }

  if (recoveryP95 > normalP95 * 2) {
    recommendations.push('Slow recovery detected - review connection pooling and cleanup');
  }

  if (recommendations.length === 0) {
    recommendations.push('System handled spike well - infrastructure is resilient');
  }

  return recommendations;
}

function generateSpikeReport(analysis) {
  return `
╔══════════════════════════════════════════════════════════════════════╗
║                      SPIKE TEST RESULTS                              ║
╠══════════════════════════════════════════════════════════════════════╣
║  Timestamp: ${analysis.timestamp}
╠══════════════════════════════════════════════════════════════════════╣
║  OVERALL METRICS                                                     ║
╠══════════════════════════════════════════════════════════════════════╣
║  Total Requests:     ${analysis.overall.totalRequests.toString().padEnd(20)}
║  Failed Requests:    ${analysis.overall.failedRequests.toString().padEnd(20)}
║  Error Rate:         ${analysis.overall.errorRate.padEnd(20)}
║  Peak VUs:           ${analysis.overall.peakVUs.toString().padEnd(20)}
╠══════════════════════════════════════════════════════════════════════╣
║  LATENCY BY PHASE (ms)                                               ║
╠══════════════════════════════════════════════════════════════════════╣
║  Normal Period:                                                      ║
║    Average: ${analysis.phaseLatency.normal.avg.toString().padEnd(10)} P95: ${analysis.phaseLatency.normal.p95.toString().padEnd(10)}
║  Spike Period (${analysis.phaseLatency.spike.requestCount} requests):
║    Average: ${analysis.phaseLatency.spike.avg.toString().padEnd(10)} P95: ${analysis.phaseLatency.spike.p95.toString().padEnd(10)}
║  Recovery Period:                                                    ║
║    Average: ${analysis.phaseLatency.recovery.avg.toString().padEnd(10)} P95: ${analysis.phaseLatency.recovery.p95.toString().padEnd(10)}
╠══════════════════════════════════════════════════════════════════════╣
║  SPIKE IMPACT ANALYSIS                                               ║
╠══════════════════════════════════════════════════════════════════════╣
║  Latency Increase During Spike:  ${analysis.impact.latencyIncreaseDuringSpike.padEnd(15)}
║  Latency After Recovery:         ${analysis.impact.latencyAfterRecovery.padEnd(15)}
║  System Recovered:               ${analysis.impact.systemRecovered ? '✅ Yes' : '❌ No'}
╠══════════════════════════════════════════════════════════════════════╣
║  RECOMMENDATIONS                                                     ║
╠══════════════════════════════════════════════════════════════════════╣
${analysis.recommendations.map(r => `║  • ${r}`).join('\n')}
╚══════════════════════════════════════════════════════════════════════╝
`;
}
