// Routes — imported by app/router.tsx
export { LoginPage } from './pages/LoginPage';
export { AuthCallbackPage } from './pages/AuthCallbackPage';
export { AuthErrorPage } from './pages/AuthErrorPage';
export { OnboardingPage } from './pages/OnboardingPage';

// Guards — imported by app/router.tsx
export { RequireAuth } from './guards/RequireAuth';
export { RequireRole } from './guards/RequireRole';

// Public hooks
export { useMeQuery, useLogout } from './api/auth.api';
