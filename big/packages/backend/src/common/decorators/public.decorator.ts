import { SetMetadata } from '@nestjs/common';

export const IS_PUBLIC_KEY = 'isPublic';

/**
 * Opt a route out of the global JwtAuthGuard.
 * Use for: login redirects, OAuth callbacks, health checks, webhooks, scanner callbacks.
 */
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
