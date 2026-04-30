# Load Testing with k6

This directory contains performance and load tests for the GigaChad GRC platform using [k6](https://k6.io/).

## Installation

### macOS
```bash
brew install k6
```

### Linux
```bash
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update
sudo apt-get install k6
```

### Docker
```bash
docker pull grafana/k6
```

## Test Types

| Test | File | Purpose | Duration | VUs |
|------|------|---------|----------|-----|
| Smoke | `smoke-test.js` | Quick verification | 30s | 1 |
| Load | `api-load-test.js` | Normal load simulation | ~16m | 10-100 |
| Stress | `stress-test.js` | Find breaking points | ~23m | 10-300 |
| Spike | `spike-test.js` | Sudden traffic spikes | ~5m | 10-500 |
| Soak | `soak-test.js` | Memory leak detection | 30m | 50 |

## Running Tests

### Quick Smoke Test
```bash
# Verify system is working
k6 run tests/load/smoke-test.js
```

### Load Test
```bash
# Normal expected load
k6 run tests/load/api-load-test.js

# Custom VUs and duration
k6 run --vus 100 --duration 10m tests/load/api-load-test.js
```

### Stress Test
```bash
# Find system limits
k6 run tests/load/stress-test.js
```

### Spike Test
```bash
# Test traffic spike handling
k6 run tests/load/spike-test.js
```

### Soak Test
```bash
# Memory leak detection (30 minutes)
k6 run tests/load/soak-test.js

# Custom duration
K6_SOAK_DURATION=1h k6 run tests/load/soak-test.js
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `K6_BASE_URL` | `http://localhost:3001` | Base URL of the application |
| `K6_API_TOKEN` | (empty) | API token for authenticated requests |
| `K6_VUS` | (varies) | Number of virtual users |
| `K6_DURATION` | (varies) | Test duration |
| `K6_SOAK_DURATION` | `30m` | Duration for soak test |

### Example with Environment Variables
```bash
K6_BASE_URL=https://staging.grc.example.com \
K6_API_TOKEN=your-api-token \
k6 run tests/load/api-load-test.js
```

## Using Docker

```bash
# Run smoke test
docker run -i grafana/k6 run - <tests/load/smoke-test.js

# With environment variables
docker run -i \
  -e K6_BASE_URL=http://host.docker.internal:3001 \
  grafana/k6 run - <tests/load/smoke-test.js
```

## Performance Thresholds

### Default Thresholds
- P50 response time < 500ms
- P90 response time < 1000ms
- P95 response time < 2000ms
- P99 response time < 5000ms
- Error rate < 1%
- Request rate > 10/s

### Stress Test Thresholds (relaxed)
- P95 response time < 5000ms
- Error rate < 10%

### Spike Test Thresholds (relaxed)
- P95 response time < 10000ms
- Error rate < 20%

## Test Results

Results are saved to `tests/load/results/`:
- `smoke-test-summary.json`
- `api-load-test-summary.json`
- `stress-test-summary.json`
- `spike-test-summary.json`
- `soak-test-summary.json`

## Grafana Dashboard

For real-time monitoring, you can output k6 metrics to InfluxDB/Grafana:

```bash
k6 run \
  --out influxdb=http://localhost:8086/k6 \
  tests/load/api-load-test.js
```

## CI Integration

Load tests can be integrated into CI pipelines:

```yaml
- name: Run Load Tests
  run: |
    k6 run tests/load/smoke-test.js
  env:
    K6_BASE_URL: ${{ secrets.STAGING_URL }}
    K6_API_TOKEN: ${{ secrets.API_TOKEN }}
```

## Interpreting Results

### Good Performance ✅
- Error rate < 1%
- P95 latency < 2000ms
- Consistent response times over time
- System recovers quickly after spikes

### Warning Signs ⚠️
- Error rate between 1-5%
- P95 latency between 2-5 seconds
- Latency increasing over time
- Slow recovery after spikes

### Critical Issues 🔴
- Error rate > 5%
- P95 latency > 5 seconds
- Server errors (5xx) increasing
- System doesn't recover from load

## Troubleshooting

### "Connection refused" errors
- Ensure the target service is running
- Check `K6_BASE_URL` is correct
- Verify network connectivity

### High error rates
- Check authentication configuration
- Review server logs for errors
- Verify API endpoints are correct

### Slow response times
- Check database performance
- Review server resource utilization
- Look for N+1 query issues

## Best Practices

1. **Start with smoke tests** - Verify basic functionality before load testing
2. **Run load tests in isolation** - Don't test against production with other users
3. **Monitor server metrics** - CPU, memory, database connections during tests
4. **Use realistic think times** - Simulate actual user behavior
5. **Test incrementally** - Start with lower loads and increase gradually
6. **Document baselines** - Keep records of normal performance for comparison




