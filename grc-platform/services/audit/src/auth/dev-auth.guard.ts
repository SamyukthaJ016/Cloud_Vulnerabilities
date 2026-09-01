/**
 * Re-export the Keycloak JWT guard from the shared module for existing imports.
 *
 * NOTE: This guard has been centralized in @gigachad-grc/shared.
 * New code should import directly from '@gigachad-grc/shared' instead.
 */
export {
  JwtAuthGuard,
  UserDecorator as User,
  AuthUserContext as UserContext,
} from '@gigachad-grc/shared';
