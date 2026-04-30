// Dashboard Widget Types and Definitions

export enum WidgetType {
  KPI_CARD = 'kpi_card',
  PIE_CHART = 'pie_chart',
  DONUT_CHART = 'donut_chart',
  BAR_CHART = 'bar_chart',
  LINE_CHART = 'line_chart',
  TABLE = 'table',
  HEATMAP = 'heatmap',
  PROGRESS = 'progress',
  LIST = 'list',
  GAUGE = 'gauge',
  MARKDOWN = 'markdown',
  IFRAME = 'iframe',
}

export enum DataSourceType {
  CONTROLS = 'controls',
  RISKS = 'risks',
  POLICIES = 'policies',
  VENDORS = 'vendors',
  EVIDENCE = 'evidence',
  EMPLOYEES = 'employees',
  AUDITS = 'audits',
  INTEGRATIONS = 'integrations',
  FRAMEWORKS = 'frameworks',
}

export enum FilterOperator {
  EQ = 'eq',
  NEQ = 'neq',
  GT = 'gt',
  GTE = 'gte',
  LT = 'lt',
  LTE = 'lte',
  CONTAINS = 'contains',
  IN = 'in',
  NOT_IN = 'not_in',
  IS_NULL = 'is_null',
  IS_NOT_NULL = 'is_not_null',
}

export enum AggregationFunction {
  COUNT = 'count',
  SUM = 'sum',
  AVG = 'avg',
  MIN = 'min',
  MAX = 'max',
}

export interface QueryFilter {
  field: string;
  operator: FilterOperator;
  value: string | number | boolean | string[] | number[] | null;
}

export interface QueryAggregation {
  field: string;
  function: AggregationFunction;
  alias: string;
}

export interface QueryOrderBy {
  field: string;
  direction: 'asc' | 'desc';
}

export interface TimeRange {
  field: string;
  start?: string;
  end?: string;
  preset?: 'last_7_days' | 'last_30_days' | 'last_90_days' | 'this_month' | 'this_quarter' | 'this_year';
}

export interface DataQuery {
  source: DataSourceType;
  filters?: QueryFilter[];
  groupBy?: string;
  aggregations?: QueryAggregation[];
  orderBy?: QueryOrderBy;
  limit?: number;
  timeRange?: TimeRange;
}

export interface WidgetPosition {
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface WidgetConfig {
  // Common
  colors?: string[];
  showLegend?: boolean;
  showValues?: boolean;
  valueFormat?: string;
  linkTemplate?: string;

  // Chart-specific
  xAxisField?: string;
  yAxisField?: string;
  orientation?: 'horizontal' | 'vertical';

  // KPI-specific
  metricField?: string;
  comparisonPeriod?: string;
  thresholds?: { value: number; color: string }[];

  // Table-specific
  columns?: { field: string; header: string; width?: number }[];
  pageSize?: number;

  // Progress/Gauge specific
  targetValue?: number;
  maxValue?: number;

  // Markdown/IFrame
  markdownContent?: string;
  iframeUrl?: string;
}

export interface DashboardWidget {
  id: string;
  widgetType: WidgetType;
  title: string;
  config: WidgetConfig;
  dataSource: DataQuery;
  position: WidgetPosition;
  refreshRate?: number;
  createdAt: string;
  updatedAt: string;
}

export interface DashboardLayout {
  cols?: number;
  rowHeight?: number;
  margin?: [number, number];
  containerPadding?: [number, number];
}

export interface Dashboard {
  id: string;
  name: string;
  description: string | null;
  isTemplate: boolean;
  isDefault: boolean;
  layout: DashboardLayout;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  widgets: DashboardWidget[];
  creator?: {
    id: string;
    displayName: string;
    email: string;
  };
}

// Widget type definitions with metadata
export interface WidgetTypeDefinition {
  type: WidgetType;
  name: string;
  description: string;
  icon: string;
  category: 'charts' | 'metrics' | 'tables' | 'content';
  defaultSize: { w: number; h: number };
  minSize: { w: number; h: number };
  maxSize: { w: number; h: number };
  configOptions: string[];
  requiresDataSource: boolean;
}

export const WIDGET_TYPES: Record<WidgetType, WidgetTypeDefinition> = {
  [WidgetType.KPI_CARD]: {
    type: WidgetType.KPI_CARD,
    name: 'KPI Card',
    description: 'Single metric with optional trend comparison',
    icon: 'hashtag',
    category: 'metrics',
    defaultSize: { w: 3, h: 2 },
    minSize: { w: 2, h: 2 },
    maxSize: { w: 6, h: 3 },
    configOptions: ['metricField', 'comparisonPeriod', 'thresholds', 'valueFormat'],
    requiresDataSource: true,
  },
  [WidgetType.PIE_CHART]: {
    type: WidgetType.PIE_CHART,
    name: 'Pie Chart',
    description: 'Distribution chart showing proportions',
    icon: 'chart-pie',
    category: 'charts',
    defaultSize: { w: 4, h: 3 },
    minSize: { w: 3, h: 2 },
    maxSize: { w: 6, h: 4 },
    configOptions: ['colors', 'showLegend', 'showValues'],
    requiresDataSource: true,
  },
  [WidgetType.DONUT_CHART]: {
    type: WidgetType.DONUT_CHART,
    name: 'Donut Chart',
    description: 'Ring chart with center value',
    icon: 'chart-pie',
    category: 'charts',
    defaultSize: { w: 4, h: 3 },
    minSize: { w: 3, h: 2 },
    maxSize: { w: 6, h: 4 },
    configOptions: ['colors', 'showLegend', 'showValues', 'metricField'],
    requiresDataSource: true,
  },
  [WidgetType.BAR_CHART]: {
    type: WidgetType.BAR_CHART,
    name: 'Bar Chart',
    description: 'Comparison chart with bars',
    icon: 'chart-bar',
    category: 'charts',
    defaultSize: { w: 6, h: 3 },
    minSize: { w: 4, h: 2 },
    maxSize: { w: 12, h: 5 },
    configOptions: ['colors', 'orientation', 'xAxisField', 'yAxisField', 'showValues'],
    requiresDataSource: true,
  },
  [WidgetType.LINE_CHART]: {
    type: WidgetType.LINE_CHART,
    name: 'Line Chart',
    description: 'Time series or trend chart',
    icon: 'chart-line',
    category: 'charts',
    defaultSize: { w: 6, h: 3 },
    minSize: { w: 4, h: 2 },
    maxSize: { w: 12, h: 5 },
    configOptions: ['colors', 'xAxisField', 'yAxisField', 'showValues'],
    requiresDataSource: true,
  },
  [WidgetType.TABLE]: {
    type: WidgetType.TABLE,
    name: 'Data Table',
    description: 'Sortable and filterable data table',
    icon: 'table',
    category: 'tables',
    defaultSize: { w: 6, h: 4 },
    minSize: { w: 4, h: 3 },
    maxSize: { w: 12, h: 8 },
    configOptions: ['columns', 'pageSize', 'linkTemplate'],
    requiresDataSource: true,
  },
  [WidgetType.HEATMAP]: {
    type: WidgetType.HEATMAP,
    name: 'Heat Map',
    description: 'Matrix visualization for risk or priority',
    icon: 'grid',
    category: 'charts',
    defaultSize: { w: 4, h: 3 },
    minSize: { w: 3, h: 2 },
    maxSize: { w: 6, h: 5 },
    configOptions: ['xAxisField', 'yAxisField', 'colors'],
    requiresDataSource: true,
  },
  [WidgetType.PROGRESS]: {
    type: WidgetType.PROGRESS,
    name: 'Progress Bar',
    description: 'Goal progress visualization',
    icon: 'progress',
    category: 'metrics',
    defaultSize: { w: 4, h: 2 },
    minSize: { w: 3, h: 1 },
    maxSize: { w: 8, h: 3 },
    configOptions: ['targetValue', 'thresholds', 'valueFormat'],
    requiresDataSource: true,
  },
  [WidgetType.LIST]: {
    type: WidgetType.LIST,
    name: 'List',
    description: 'Ranked or recent items list',
    icon: 'list',
    category: 'tables',
    defaultSize: { w: 4, h: 4 },
    minSize: { w: 3, h: 2 },
    maxSize: { w: 6, h: 8 },
    configOptions: ['columns', 'linkTemplate'],
    requiresDataSource: true,
  },
  [WidgetType.GAUGE]: {
    type: WidgetType.GAUGE,
    name: 'Gauge',
    description: 'Percentage or score gauge',
    icon: 'gauge',
    category: 'metrics',
    defaultSize: { w: 3, h: 2 },
    minSize: { w: 2, h: 2 },
    maxSize: { w: 4, h: 3 },
    configOptions: ['maxValue', 'thresholds', 'valueFormat'],
    requiresDataSource: true,
  },
  [WidgetType.MARKDOWN]: {
    type: WidgetType.MARKDOWN,
    name: 'Text / Markdown',
    description: 'Static text, notes, or instructions',
    icon: 'document-text',
    category: 'content',
    defaultSize: { w: 4, h: 2 },
    minSize: { w: 2, h: 1 },
    maxSize: { w: 12, h: 8 },
    configOptions: ['markdownContent'],
    requiresDataSource: false,
  },
  [WidgetType.IFRAME]: {
    type: WidgetType.IFRAME,
    name: 'Embedded Content',
    description: 'Embed external content via URL',
    icon: 'globe',
    category: 'content',
    defaultSize: { w: 6, h: 4 },
    minSize: { w: 4, h: 3 },
    maxSize: { w: 12, h: 8 },
    configOptions: ['iframeUrl'],
    requiresDataSource: false,
  },
};

// Color palettes for charts
export const CHART_COLORS = {
  default: ['#6366f1', '#22c55e', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4', '#ec4899', '#84cc16'],
  status: {
    implemented: '#22c55e',
    in_progress: '#f59e0b',
    not_started: '#6b7280',
    not_applicable: '#3b82f6',
  },
  risk: {
    critical: '#dc2626',
    high: '#f97316',
    medium: '#eab308',
    low: '#22c55e',
    very_low: '#6b7280',
  },
  policy: {
    published: '#22c55e',
    approved: '#3b82f6',
    in_review: '#f59e0b',
    draft: '#6b7280',
    retired: '#ef4444',
  },
};

// Default widgets for new dashboards
export const DEFAULT_WIDGETS: Partial<DashboardWidget>[] = [
  {
    widgetType: WidgetType.KPI_CARD,
    title: 'Compliance Score',
    position: { x: 0, y: 0, w: 3, h: 2 },
    dataSource: {
      source: DataSourceType.CONTROLS,
      aggregations: [{ field: 'status', function: AggregationFunction.COUNT, alias: 'count' }],
    },
    config: {
      metricField: 'count',
      valueFormat: '{value}%',
      thresholds: [
        { value: 70, color: '#22c55e' },
        { value: 40, color: '#f59e0b' },
        { value: 0, color: '#ef4444' },
      ],
    },
  },
  {
    widgetType: WidgetType.PIE_CHART,
    title: 'Control Status',
    position: { x: 3, y: 0, w: 4, h: 3 },
    dataSource: {
      source: DataSourceType.CONTROLS,
      groupBy: 'status',
    },
    config: {
      colors: Object.values(CHART_COLORS.status),
      showLegend: true,
    },
  },
  {
    widgetType: WidgetType.BAR_CHART,
    title: 'Risks by Severity',
    position: { x: 7, y: 0, w: 5, h: 3 },
    dataSource: {
      source: DataSourceType.RISKS,
      groupBy: 'initialSeverity',
    },
    config: {
      colors: Object.values(CHART_COLORS.risk),
      orientation: 'horizontal',
    },
  },
];

