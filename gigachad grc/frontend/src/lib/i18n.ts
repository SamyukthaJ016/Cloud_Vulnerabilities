/**
 * Internationalization (i18n) Configuration
 * 
 * To enable i18n, install these packages:
 * npm install i18next react-i18next i18next-browser-languagedetector
 * 
 * This module works as a pass-through when i18n packages aren't installed.
 */

// Available languages
export const AVAILABLE_LANGUAGES = [
  { code: 'en', name: 'English', nativeName: 'English' },
  { code: 'es', name: 'Spanish', nativeName: 'Español' },
  { code: 'fr', name: 'French', nativeName: 'Français' },
  { code: 'de', name: 'German', nativeName: 'Deutsch' },
];

// Translation strings (used when i18n packages aren't installed)
export const translations = {
  en: {
    common: {
      loading: 'Loading...',
      save: 'Save',
      cancel: 'Cancel',
      delete: 'Delete',
      edit: 'Edit',
      create: 'Create',
      search: 'Search',
      filter: 'Filter',
      export: 'Export',
      import: 'Import',
      refresh: 'Refresh',
      back: 'Back',
      next: 'Next',
      previous: 'Previous',
      submit: 'Submit',
      confirm: 'Confirm',
      close: 'Close',
      view: 'View',
      actions: 'Actions',
      status: 'Status',
      name: 'Name',
      description: 'Description',
      category: 'Category',
      type: 'Type',
      date: 'Date',
      createdAt: 'Created At',
      updatedAt: 'Updated At',
      createdBy: 'Created By',
      owner: 'Owner',
      yes: 'Yes',
      no: 'No',
      all: 'All',
      none: 'None',
      selected: 'Selected',
      noResults: 'No results found',
      error: 'Error',
      success: 'Success',
      warning: 'Warning',
      info: 'Information',
    },
    navigation: {
      dashboard: 'Dashboard',
      controls: 'Controls',
      frameworks: 'Frameworks',
      risks: 'Risks',
      policies: 'Policies',
      vendors: 'Vendors',
      evidence: 'Evidence',
      integrations: 'Integrations',
      audits: 'Audits',
      trustCenter: 'Trust Center',
      employees: 'Employees',
      assets: 'Assets',
      settings: 'Settings',
      help: 'Help',
      account: 'Account',
      logout: 'Logout',
    },
    errors: {
      generic: 'Something went wrong. Please try again.',
      notFound: 'Page not found',
      unauthorized: 'You are not authorized to access this resource.',
      forbidden: 'Access forbidden',
      serverError: 'Server error. Please try again later.',
      networkError: 'Network error. Please check your connection.',
      validation: 'Please check your input and try again.',
    },
  },
};

// Helper to get language name by code
export function getLanguageName(code: string): string {
  const lang = AVAILABLE_LANGUAGES.find((l) => l.code === code);
  return lang ? lang.name : code;
}

// Helper to get native language name by code
export function getNativeLanguageName(code: string): string {
  const lang = AVAILABLE_LANGUAGES.find((l) => l.code === code);
  return lang ? lang.nativeName : code;
}

// Simple translation function that works without i18n packages
export function t(key: string, _options?: Record<string, unknown>): string {
  const keys = key.split('.');
  let value: unknown = translations.en;
  
  for (const k of keys) {
    if (value && typeof value === 'object' && k in value) {
      value = (value as Record<string, unknown>)[k];
    } else {
      return key; // Return key if not found
    }
  }
  
  return typeof value === 'string' ? value : key;
}

// i18n initialization (async to allow optional dynamic import)
let i18nInstance: unknown = null;
let initializationPromise: Promise<void> | null = null;

export async function initI18n(): Promise<void> {
  if (initializationPromise) return initializationPromise;
  
  initializationPromise = (async () => {
    try {
      // Try to dynamically import i18n packages
      const i18nPackage = 'i18next';
      const reactI18nPackage = 'react-i18next';
      const detectorPackage = 'i18next-browser-languagedetector';
      
      const [i18n, { initReactI18next }, LanguageDetector] = await Promise.all([
        import(/* @vite-ignore */ i18nPackage),
        import(/* @vite-ignore */ reactI18nPackage),
        import(/* @vite-ignore */ detectorPackage),
      ]);
      
      await i18n.default
        .use(LanguageDetector.default)
        .use(initReactI18next)
        .init({
          resources: {
            en: { translation: translations.en },
          },
          fallbackLng: 'en',
          interpolation: {
            escapeValue: false,
          },
          detection: {
            order: ['localStorage', 'navigator', 'htmlTag'],
            caches: ['localStorage'],
          },
        });
      
      i18nInstance = i18n.default;
      console.info('[i18n] Initialized successfully');
    } catch {
      console.info('[i18n] Packages not installed - using built-in translations');
      console.debug('[i18n] To enable full i18n: npm install i18next react-i18next i18next-browser-languagedetector');
    }
  })();
  
  return initializationPromise;
}

// Export functions that work with or without i18n packages
export function getCurrentLanguage(): string {
  if (i18nInstance && typeof i18nInstance === 'object' && 'language' in i18nInstance) {
    return (i18nInstance as { language: string }).language || 'en';
  }
  return localStorage.getItem('preferredLanguage') || 'en';
}

export async function changeLanguage(languageCode: string): Promise<void> {
  localStorage.setItem('preferredLanguage', languageCode);
  
  if (i18nInstance && typeof i18nInstance === 'object' && 'changeLanguage' in i18nInstance) {
    await (i18nInstance as { changeLanguage: (code: string) => Promise<void> }).changeLanguage(languageCode);
  }
}

// Initialize on module load
initI18n().catch(console.error);

// Default export for compatibility
export default {
  t,
  getCurrentLanguage,
  changeLanguage,
  AVAILABLE_LANGUAGES,
};
