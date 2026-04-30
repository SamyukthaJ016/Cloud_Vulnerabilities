import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';

/**
 * Minimal E2E smoke test for MCP workflow HTTP surface.
 * Verifies that the workflow listing and execution endpoints are reachable.
 */
describe('MCPWorkflowController (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleRef.createNestApplication();
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('/api/mcp/workflows (GET) responds', async () => {
    const res = await request(app.getHttpServer()).get('/api/mcp/workflows').send();
    expect(res.status).toBeGreaterThanOrEqual(200);
    expect(res.status).toBeLessThan(500);
  });

  it('/api/mcp/workflows/:id/execute (POST) responds for a known workflow', async () => {
    // Use a built-in workflow id; even if it fails internally, endpoint should respond
    const res = await request(app.getHttpServer())
      .post('/api/mcp/workflows/evidence-collection/execute')
      .send({});

    expect(res.status).toBeGreaterThanOrEqual(200);
    expect(res.status).toBeLessThan(500);
  });
});


