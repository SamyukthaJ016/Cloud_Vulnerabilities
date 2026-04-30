import toast, { ToastOptions } from 'react-hot-toast';
import { AxiosError } from 'axios';

// ===========================================
// Toast Configuration
// ===========================================

const defaultOptions: ToastOptions = {
  duration: 4000,
  position: 'top-right',
};

const successOptions: ToastOptions = {
  ...defaultOptions,
  duration: 3000,
  style: {
    background: '#10B981',
    color: '#fff',
    fontWeight: 500,
  },
  iconTheme: {
    primary: '#fff',
    secondary: '#10B981',
  },
};

const errorOptions: ToastOptions = {
  ...defaultOptions,
  duration: 5000,
  style: {
    background: '#EF4444',
    color: '#fff',
    fontWeight: 500,
  },
  iconTheme: {
    primary: '#fff',
    secondary: '#EF4444',
  },
};

const warningOptions: ToastOptions = {
  ...defaultOptions,
  duration: 4000,
  style: {
    background: '#F59E0B',
    color: '#fff',
    fontWeight: 500,
  },
  iconTheme: {
    primary: '#fff',
    secondary: '#F59E0B',
  },
};

const infoOptions: ToastOptions = {
  ...defaultOptions,
  style: {
    background: '#3B82F6',
    color: '#fff',
    fontWeight: 500,
  },
  iconTheme: {
    primary: '#fff',
    secondary: '#3B82F6',
  },
};

// ===========================================
// Error Message Extraction
// ===========================================

interface ApiErrorResponse {
  message?: string | string[];
  error?: string;
  statusCode?: number;
}

/**
 * Extracts a user-friendly error message from various error types
 */
export function extractErrorMessage(error: unknown): string {
  // Handle Axios errors
  if (error && typeof error === 'object' && 'isAxiosError' in error) {
    const axiosError = error as AxiosError<ApiErrorResponse>;
    
    // Check for response data
    if (axiosError.response?.data) {
      const data = axiosError.response.data;
      
      // Handle array of messages (validation errors)
      if (Array.isArray(data.message)) {
        return data.message.join(', ');
      }
      
      // Handle single message
      if (data.message) {
        return data.message;
      }
      
      // Handle error field
      if (data.error) {
        return data.error;
      }
    }
    
    // Handle network errors
    if (axiosError.code === 'NETWORK_ERROR' || axiosError.message === 'Network Error') {
      return 'Unable to connect to the server. Please check your internet connection.';
    }
    
    // Handle timeout
    if (axiosError.code === 'ECONNABORTED') {
      return 'Request timed out. Please try again.';
    }
    
    // Handle specific status codes
    if (axiosError.response?.status) {
      switch (axiosError.response.status) {
        case 400:
          return 'Invalid request. Please check your input.';
        case 401:
          return 'You are not authenticated. Please log in.';
        case 403:
          return 'You do not have permission to perform this action.';
        case 404:
          return 'The requested resource was not found.';
        case 409:
          return 'This action conflicts with existing data.';
        case 422:
          return 'Validation failed. Please check your input.';
        case 429:
          return 'Too many requests. Please wait a moment.';
        case 500:
          return 'An unexpected server error occurred. Please try again.';
        case 502:
        case 503:
        case 504:
          return 'The server is temporarily unavailable. Please try again later.';
      }
    }
    
    return axiosError.message || 'An unexpected error occurred.';
  }
  
  // Handle standard Error objects
  if (error instanceof Error) {
    return error.message;
  }
  
  // Handle string errors
  if (typeof error === 'string') {
    return error;
  }
  
  // Default message
  return 'An unexpected error occurred. Please try again.';
}

// ===========================================
// Toast Hook
// ===========================================

export function useToast() {
  const showSuccess = (message: string, options?: ToastOptions) => {
    return toast.success(message, { ...successOptions, ...options });
  };

  const showError = (error: unknown, fallbackMessage?: string) => {
    const message = extractErrorMessage(error) || fallbackMessage || 'An error occurred';
    return toast.error(message, errorOptions);
  };

  const showWarning = (message: string, options?: ToastOptions) => {
    return toast(message, { ...warningOptions, icon: '⚠️', ...options });
  };

  const showInfo = (message: string, options?: ToastOptions) => {
    return toast(message, { ...infoOptions, icon: 'ℹ️', ...options });
  };

  const showLoading = (message: string) => {
    return toast.loading(message, {
      ...defaultOptions,
      duration: Infinity,
    });
  };

  const dismiss = (toastId?: string) => {
    if (toastId) {
      toast.dismiss(toastId);
    } else {
      toast.dismiss();
    }
  };

  const showPromise = <T,>(
    promise: Promise<T>,
    messages: {
      loading: string;
      success: string | ((data: T) => string);
      error: string | ((err: unknown) => string);
    }
  ) => {
    return toast.promise(
      promise,
      {
        loading: messages.loading,
        success: messages.success,
        error: (err) => {
          if (typeof messages.error === 'function') {
            return messages.error(err);
          }
          return extractErrorMessage(err) || messages.error;
        },
      },
      {
        ...defaultOptions,
        success: successOptions,
        error: errorOptions,
      }
    );
  };

  return {
    success: showSuccess,
    error: showError,
    warning: showWarning,
    info: showInfo,
    loading: showLoading,
    dismiss,
    promise: showPromise,
  };
}

// ===========================================
// Standalone Toast Functions
// ===========================================

export const toastSuccess = (message: string) => toast.success(message, successOptions);
export const toastError = (error: unknown) => toast.error(extractErrorMessage(error), errorOptions);
export const toastWarning = (message: string) => toast(message, { ...warningOptions, icon: '⚠️' });
export const toastInfo = (message: string) => toast(message, { ...infoOptions, icon: 'ℹ️' });

export default useToast;





