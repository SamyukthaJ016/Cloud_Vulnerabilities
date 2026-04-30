import { Global, Module } from '@nestjs/common';
import { BullModule } from '@nestjs/bullmq';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { QUEUE_NAMES } from './queues.constants';

/**
 * BullMQ bootstrap. Registers the connection and all named queues.
 * Consumers (workers) live in their owning module.
 *   - webhook-delivery → webhooks-outbound module
 */
@Global()
@Module({
  imports: [
    BullModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        connection: {
          host: config.get<string>('redis.host'),
          port: config.get<number>('redis.port'),
          password: config.get<string>('redis.password') || undefined,
        },
      }),
    }),
    BullModule.registerQueue({ name: QUEUE_NAMES.WEBHOOK_DELIVERY }),
  ],
  exports: [BullModule],
})
export class QueueModule {}
