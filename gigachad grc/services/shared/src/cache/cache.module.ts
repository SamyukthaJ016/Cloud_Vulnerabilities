import { Module, Global, DynamicModule } from '@nestjs/common';
import { CacheService } from './cache.service';

export interface CacheModuleOptions {
  /** Default TTL in seconds (default: 300 = 5 minutes) */
  defaultTtl?: number;
  /** Maximum number of items in cache (default: 1000) */
  maxSize?: number;
  /** Enable debug logging (default: false) */
  debug?: boolean;
}

@Global()
@Module({})
export class CacheModule {
  static forRoot(options: CacheModuleOptions = {}): DynamicModule {
    return {
      module: CacheModule,
      providers: [
        {
          provide: 'CACHE_OPTIONS',
          useValue: {
            defaultTtl: options.defaultTtl ?? 300,
            maxSize: options.maxSize ?? 1000,
            debug: options.debug ?? false,
          },
        },
        CacheService,
      ],
      exports: [CacheService],
    };
  }
}





