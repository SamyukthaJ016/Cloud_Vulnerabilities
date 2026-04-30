import { createContext, useContext, useState, useEffect, ReactNode } from 'react';

export interface BrandingConfig {
  platformName: string;
  logoUrl: string;
  faviconUrl: string;
  primaryColor: string;
}

const DEFAULT_BRANDING: BrandingConfig = {
  platformName: 'GigaChad GRC',
  logoUrl: '/logo.png',
  faviconUrl: '/logo.png',
  primaryColor: '#6366f1', // Brand indigo
};

interface BrandingContextType {
  branding: BrandingConfig;
  updateBranding: (config: Partial<BrandingConfig>) => Promise<void>;
  isLoading: boolean;
}

const BrandingContext = createContext<BrandingContextType | null>(null);

const STORAGE_KEY = 'grc-branding';

export function BrandingProvider({ children }: { children: ReactNode }) {
  const [branding, setBranding] = useState<BrandingConfig>(DEFAULT_BRANDING);
  const [isLoading, setIsLoading] = useState(true);

  // Load branding from localStorage on mount
  useEffect(() => {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      try {
        const parsed = JSON.parse(stored);
        // Migrate old favicon values to use logo.png
        if (parsed.faviconUrl === '/favicon.ico' || parsed.faviconUrl === '/favicon.svg' || !parsed.faviconUrl) {
          parsed.faviconUrl = '/logo.png';
          localStorage.setItem(STORAGE_KEY, JSON.stringify({ ...DEFAULT_BRANDING, ...parsed }));
        }
        setBranding({ ...DEFAULT_BRANDING, ...parsed });
      } catch {
        // Invalid JSON, use defaults
      }
    }
    setIsLoading(false);
  }, []);

  // Update document title when platform name changes
  useEffect(() => {
    if (branding.platformName !== DEFAULT_BRANDING.platformName) {
      document.title = branding.platformName;
    }
  }, [branding.platformName]);

  // Update favicon when it changes
  useEffect(() => {
    const link = document.querySelector("link[rel~='icon']") as HTMLLinkElement;
    // Always use logo.png as favicon (default), unless explicitly changed
    const faviconUrl = branding.faviconUrl || '/logo.png';
    if (link) {
      link.href = faviconUrl;
    }
  }, [branding.faviconUrl]);

  const updateBranding = async (config: Partial<BrandingConfig>) => {
    const newBranding = { ...branding, ...config };
    setBranding(newBranding);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(newBranding));
    
    // In a real app, you'd also save to the backend:
    // await api.patch('/api/organization/branding', config);
  };

  return (
    <BrandingContext.Provider value={{ branding, updateBranding, isLoading }}>
      {children}
    </BrandingContext.Provider>
  );
}

export function useBranding() {
  const context = useContext(BrandingContext);
  if (!context) {
    throw new Error('useBranding must be used within a BrandingProvider');
  }
  return context;
}

// Hook for components that just need to read branding (with fallback)
export function useBrandingConfig(): BrandingConfig {
  const context = useContext(BrandingContext);
  return context?.branding || DEFAULT_BRANDING;
}

