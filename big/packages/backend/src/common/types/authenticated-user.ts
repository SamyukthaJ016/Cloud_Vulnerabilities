/**
 * Shape attached to `req.user` by JwtStrategy.
 * Every tenant-scoped service/controller can rely on this being present
 * (unless the route is @Public).
 */
export interface AuthenticatedUser {
  userId: string;
  orgId: string | null; // null for users not yet assigned to an org
  roleKey: string | null;
  email: string;
}
