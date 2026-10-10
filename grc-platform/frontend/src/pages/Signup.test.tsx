import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import Signup from './Signup';
import Login from './Login';

const auth = vi.hoisted(() => ({ isAuthenticated: false, isLoading: false, accessPending: false, authError: null, login: vi.fn(), loginWithGoogle: vi.fn(), register: vi.fn(), logout: vi.fn() }));
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => auth }));
vi.mock('@/contexts/BrandingContext', () => ({ useBrandingConfig: () => ({ logoUrl: '/logo.svg', platformName: 'CloudGuard' }) }));

describe('Sign-up and Google sign-in', () => {
  beforeEach(() => vi.clearAllMocks());
  it('offers Google sign-up and email registration', async () => {
    render(<MemoryRouter><Signup /></MemoryRouter>);
    fireEvent.click(screen.getByRole('button', { name: 'Sign up with Google' }));
    await waitFor(() => expect(auth.loginWithGoogle).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Continue with email' })).not.toBeDisabled());
    fireEvent.change(screen.getByLabelText('Email address'), { target: { value: 'new@example.test' } });
    fireEvent.click(screen.getByRole('button', { name: 'Continue with email' }));
    await waitFor(() => expect(auth.register).toHaveBeenCalledWith('new@example.test'));
    expect(screen.getByRole('link', { name: 'Sign in' })).toHaveAttribute('href', '/login');
  });
  it('links sign-in to the sign-up page', () => {
    render(<MemoryRouter><Login /></MemoryRouter>);
    expect(screen.getByRole('link', { name: 'Create an account' })).toHaveAttribute('href', '/signup');
    expect(screen.getByRole('button', { name: 'Continue with Google' })).toBeVisible();
  });
  it('reports a failed redirect and allows retry', async () => {
    auth.loginWithGoogle.mockRejectedValueOnce(new Error('unavailable'));
    render(<MemoryRouter><Signup /></MemoryRouter>);
    fireEvent.click(screen.getByRole('button', { name: 'Sign up with Google' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Please try again');
    expect(screen.getByRole('button', { name: 'Sign up with Google' })).not.toBeDisabled();
  });
});
