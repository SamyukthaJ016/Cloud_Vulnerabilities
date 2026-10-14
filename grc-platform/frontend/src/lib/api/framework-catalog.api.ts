import { api } from './client';

export interface CatalogRequirement {
  reference: string;
  title: string;
  description: string;
  isCategory: boolean;
  children?: CatalogRequirement[];
}

export interface CatalogFrameworkSummary {
  id: string;
  name: string;
  version: string;
  source: string;
  isActivated?: boolean;
}

export interface CatalogFrameworkDetail extends CatalogFrameworkSummary {
  requirements: CatalogRequirement[];
}

export const frameworkCatalogApi = {
  list: async (): Promise<CatalogFrameworkSummary[]> => {
    const response = await api.get<CatalogFrameworkSummary[]>('/api/frameworks/catalog/status');
    return response.data;
  },
  detail: async (id: string): Promise<CatalogFrameworkDetail> => {
    const response = await api.get<CatalogFrameworkDetail>(
      `/api/frameworks/catalog/${encodeURIComponent(id)}`
    );
    return response.data;
  },
};
