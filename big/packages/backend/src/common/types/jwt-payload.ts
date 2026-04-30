/**
 * Payload signed into the app JWT (flow P).
 * Kept minimal — never put secrets or large objects in here.
 */
export interface JwtPayload {
  sub: string;            // user id
  email: string;
  orgId: string | null;
  roleKey: string | null;
  iat?: number;
  exp?: number;
}
