import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';

/**
 * Minimal E2E smoke test for collectors HTTP surface.
 * Verifies that the collectors endpoints are wired and respond (2xx/4xx),
 * not that full business logic works.
 */
describe('CollectorsController (e2e)', () => {
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

  it('/api/collectors (GET) responds', async () => {
    const res = await request(app.getHttpServer()).get('/api/collectors').send();
    // Service should respond (200 with data, or 400/401/403 if auth is enforced)
    expect(res.status).toBeGreaterThanOrEqual(200);
    expect(res.status).toBeLessThan(500);
  });
});


