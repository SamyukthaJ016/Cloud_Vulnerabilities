import { useCallback, useState, useEffect } from 'react';
import { 
  t as translate, 
  AVAILABLE_LANGUAGES, 
  getCurrentLanguage, 
  changeLanguage as setLanguage 
} from '@/lib/i18n';

/**
 * Custom hook for translations
 * Works with or without react-i18next installed
 */
export function useTranslation(_namespace?: string) {
  const [currentLanguage, setCurrentLanguage] = useState(getCurrentLanguage);

  // Update language state when it changes
  useEffect(() => {
    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === 'preferredLanguage' && e.newValue) {
        setCurrentLanguage(e.newValue);
      }
    };
    
    window.addEventListener('storage', handleStorageChange);
    return () => window.removeEventListener('storage', handleStorageChange);
  }, []);

  // Translation function
  const t = useCallback((key: string, options?: Record<string, unknown>): string => {
    return translate(key, options);
  }, []);

  // Change language
  const changeLanguage = useCallback(async (languageCode: string) => {
    await setLanguage(languageCode);
    setCurrentLanguage(languageCode);
  }, []);

  // Get available languages
  const availableLanguages = AVAILABLE_LANGUAGES;

  // Check if a language is supported
  const isLanguageSupported = useCallback((code: string) => {
    return AVAILABLE_LANGUAGES.some((lang) => lang.code === code);
  }, []);

  // Get current language display name
  const currentLanguageName = AVAILABLE_LANGUAGES.find(
    (lang) => lang.code === currentLanguage
  )?.name || currentLanguage;

  // Get current language native name
  const currentLanguageNativeName = AVAILABLE_LANGUAGES.find(
    (lang) => lang.code === currentLanguage
  )?.nativeName || currentLanguage;

  // Helper to translate with fallback
  const translateWithFallback = useCallback(
    (key: string, fallback: string, options?: Record<string, unknown>) => {
      const translated = t(key, options);
      return translated === key ? fallback : translated;
    },
    [t]
  );

  // Helper to format date according to locale
  const formatDate = useCallback(
    (date: Date | string, options?: Intl.DateTimeFormatOptions) => {
      const dateObj = typeof date === 'string' ? new Date(date) : date;
      return new Intl.DateTimeFormat(currentLanguage, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        ...options,
      }).format(dateObj);
    },
    [currentLanguage]
  );

  // Helper to format number according to locale
  const formatNumber = useCallback(
    (number: number, options?: Intl.NumberFormatOptions) => {
      return new Intl.NumberFormat(currentLanguage, options).format(number);
    },
    [currentLanguage]
  );

  // Helper to format currency according to locale
  const formatCurrency = useCallback(
    (amount: number, currency = 'USD') => {
      return new Intl.NumberFormat(currentLanguage, {
        style: 'currency',
        currency,
      }).format(amount);
    },
    [currentLanguage]
  );

  // Helper to format percentage
  const formatPercent = useCallback(
    (value: number, decimals = 0) => {
      return new Intl.NumberFormat(currentLanguage, {
        style: 'percent',
        minimumFractionDigits: decimals,
        maximumFractionDigits: decimals,
      }).format(value / 100);
    },
    [currentLanguage]
  );

  // Helper to get relative time
  const formatRelativeTime = useCallback(
    (date: Date | string) => {
      const dateObj = typeof date === 'string' ? new Date(date) : date;
      const now = new Date();
      const diffMs = now.getTime() - dateObj.getTime();
      const diffSecs = Math.floor(diffMs / 1000);
      const diffMins = Math.floor(diffSecs / 60);
      const diffHours = Math.floor(diffMins / 60);
      const diffDays = Math.floor(diffHours / 24);

      if (diffSecs < 60) {
        return 'Just now';
      } else if (diffMins < 60) {
        return `${diffMins} minute${diffMins !== 1 ? 's' : ''} ago`;
      } else if (diffHours < 24) {
        return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`;
      } else if (diffDays === 1) {
        return 'Yesterday';
      } else if (diffDays < 7) {
        return `${diffDays} days ago`;
      } else {
        return formatDate(dateObj);
      }
    },
    [formatDate]
  );

  return {
    // Core translation function
    t,
    // Ready state (always true for this implementation)
    ready: true,
    // Language info
    currentLanguage,
    currentLanguageName,
    currentLanguageNativeName,
    availableLanguages,
    // Language functions
    changeLanguage,
    isLanguageSupported,
    // Translation helpers
    translateWithFallback,
    // Formatting helpers
    formatDate,
    formatNumber,
    formatCurrency,
    formatPercent,
    formatRelativeTime,
  };
}

export default useTranslation;
