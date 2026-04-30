import { NestFactory } from '@nestjs/core';
import { ValidationPipe, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { json, raw } from 'express';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    rawBody: true,
    logger: ['log', 'error', 'warn', 'debug', 'verbose'],
  });

  const config = app.get(ConfigService);

  // Raw body for signature verification. Must be registered BEFORE the JSON body parser.
  //   - Razorpay webhooks (flow BG)
  //   - Scanner callbacks (flow GT): HMAC-SHA256 over (rawBody + '.' + nonce)
  app.use('/webhooks/razorpay', raw({ type: 'application/json' }));
  app.use('/scanner-callbacks', raw({ type: 'application/json' }));
  app.use(json());

  app.use(helmet());
  app.use(cookieParser());

  app.enableCors({
    origin: config.get<string>('app.corsOrigins')?.split(',') ?? [],
    credentials: true,
  });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      forbidNonWhitelisted: true,
    }),
  );

  app.setGlobalPrefix('api', { exclude: ['health', 'webhooks/(.*)', 'scanner-callbacks/(.*)'] });

  const port = config.get<number>('app.port') ?? 3000;
  await app.listen(port);
  Logger.log(`CloudGuard Control Plane listening on :${port}`, 'Bootstrap');
}

bootstrap();
