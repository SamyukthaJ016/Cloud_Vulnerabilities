import { describe, it, expect } from 'vitest';
import {
  WidgetType,
  DataSourceType,
  FilterOperator,
  AggregationFunction,
  WIDGET_TYPES,
  CHART_COLORS,
  DEFAULT_WIDGETS,
} from './dashboardWidgets';

describe('Dashboard Widgets Library', () => {
  describe('WidgetType enum', () => {
    it('has all expected widget types', () => {
      expect(WidgetType.KPI_CARD).toBe('kpi_card');
      expect(WidgetType.PIE_CHART).toBe('pie_chart');
      expect(WidgetType.DONUT_CHART).toBe('donut_chart');
      expect(WidgetType.BAR_CHART).toBe('bar_chart');
      expect(WidgetType.LINE_CHART).toBe('line_chart');
      expect(WidgetType.TABLE).toBe('table');
      expect(WidgetType.HEATMAP).toBe('heatmap');
      expect(WidgetType.PROGRESS).toBe('progress');
      expect(WidgetType.LIST).toBe('list');
      expect(WidgetType.GAUGE).toBe('gauge');
      expect(WidgetType.MARKDOWN).toBe('markdown');
      expect(WidgetType.IFRAME).toBe('iframe');
    });
  });

  describe('DataSourceType enum', () => {
    it('has all expected data source types', () => {
      expect(DataSourceType.CONTROLS).toBe('controls');
      expect(DataSourceType.RISKS).toBe('risks');
      expect(DataSourceType.POLICIES).toBe('policies');
      expect(DataSourceType.VENDORS).toBe('vendors');
      expect(DataSourceType.EVIDENCE).toBe('evidence');
      expect(DataSourceType.EMPLOYEES).toBe('employees');
      expect(DataSourceType.AUDITS).toBe('audits');
      expect(DataSourceType.INTEGRATIONS).toBe('integrations');
      expect(DataSourceType.FRAMEWORKS).toBe('frameworks');
    });
  });

  describe('FilterOperator enum', () => {
    it('has all expected filter operators', () => {
      expect(FilterOperator.EQ).toBe('eq');
      expect(FilterOperator.NEQ).toBe('neq');
      expect(FilterOperator.GT).toBe('gt');
      expect(FilterOperator.GTE).toBe('gte');
      expect(FilterOperator.LT).toBe('lt');
      expect(FilterOperator.LTE).toBe('lte');
      expect(FilterOperator.CONTAINS).toBe('contains');
      expect(FilterOperator.IN).toBe('in');
      expect(FilterOperator.NOT_IN).toBe('not_in');
      expect(FilterOperator.IS_NULL).toBe('is_null');
      expect(FilterOperator.IS_NOT_NULL).toBe('is_not_null');
    });
  });

  describe('AggregationFunction enum', () => {
    it('has all expected aggregation functions', () => {
      expect(AggregationFunction.COUNT).toBe('count');
      expect(AggregationFunction.SUM).toBe('sum');
      expect(AggregationFunction.AVG).toBe('avg');
      expect(AggregationFunction.MIN).toBe('min');
      expect(AggregationFunction.MAX).toBe('max');
    });
  });

  describe('WIDGET_TYPES', () => {
    it('has definitions for all widget types', () => {
      expect(Object.keys(WIDGET_TYPES)).toHaveLength(12);
      
      // Check that all WidgetType values have a definition
      Object.values(WidgetType).forEach((type) => {
        expect(WIDGET_TYPES[type]).toBeDefined();
      });
    });

    it('each widget type has required properties', () => {
      Object.values(WIDGET_TYPES).forEach((definition) => {
        expect(definition.type).toBeDefined();
        expect(definition.name).toBeDefined();
        expect(definition.description).toBeDefined();
        expect(definition.icon).toBeDefined();
        expect(definition.category).toBeDefined();
        expect(definition.defaultSize).toBeDefined();
        expect(definition.minSize).toBeDefined();
        expect(definition.maxSize).toBeDefined();
        expect(definition.configOptions).toBeDefined();
        expect(typeof definition.requiresDataSource).toBe('boolean');
      });
    });

    it('widget sizes are valid', () => {
      Object.values(WIDGET_TYPES).forEach((definition) => {
        // Default size should be >= min and <= max
        expect(definition.defaultSize.w).toBeGreaterThanOrEqual(definition.minSize.w);
        expect(definition.defaultSize.h).toBeGreaterThanOrEqual(definition.minSize.h);
        expect(definition.defaultSize.w).toBeLessThanOrEqual(definition.maxSize.w);
        expect(definition.defaultSize.h).toBeLessThanOrEqual(definition.maxSize.h);
      });
    });

    it('categories are valid', () => {
      const validCategories = ['charts', 'metrics', 'tables', 'content'];
      Object.values(WIDGET_TYPES).forEach((definition) => {
        expect(validCategories).toContain(definition.category);
      });
    });

    it('markdown and iframe widgets do not require data source', () => {
      expect(WIDGET_TYPES[WidgetType.MARKDOWN].requiresDataSource).toBe(false);
      expect(WIDGET_TYPES[WidgetType.IFRAME].requiresDataSource).toBe(false);
    });

    it('chart widgets require data source', () => {
      expect(WIDGET_TYPES[WidgetType.PIE_CHART].requiresDataSource).toBe(true);
      expect(WIDGET_TYPES[WidgetType.BAR_CHART].requiresDataSource).toBe(true);
      expect(WIDGET_TYPES[WidgetType.LINE_CHART].requiresDataSource).toBe(true);
    });
  });

  describe('CHART_COLORS', () => {
    it('has default color palette', () => {
      expect(CHART_COLORS.default).toBeDefined();
      expect(CHART_COLORS.default.length).toBeGreaterThan(0);
    });

    it('has status colors', () => {
      expect(CHART_COLORS.status).toBeDefined();
      expect(CHART_COLORS.status.implemented).toBeDefined();
      expect(CHART_COLORS.status.in_progress).toBeDefined();
      expect(CHART_COLORS.status.not_started).toBeDefined();
      expect(CHART_COLORS.status.not_applicable).toBeDefined();
    });

    it('has risk colors', () => {
      expect(CHART_COLORS.risk).toBeDefined();
      expect(CHART_COLORS.risk.critical).toBeDefined();
      expect(CHART_COLORS.risk.high).toBeDefined();
      expect(CHART_COLORS.risk.medium).toBeDefined();
      expect(CHART_COLORS.risk.low).toBeDefined();
      expect(CHART_COLORS.risk.very_low).toBeDefined();
    });

    it('has policy colors', () => {
      expect(CHART_COLORS.policy).toBeDefined();
      expect(CHART_COLORS.policy.published).toBeDefined();
      expect(CHART_COLORS.policy.approved).toBeDefined();
      expect(CHART_COLORS.policy.in_review).toBeDefined();
      expect(CHART_COLORS.policy.draft).toBeDefined();
      expect(CHART_COLORS.policy.retired).toBeDefined();
    });

    it('colors are valid hex codes', () => {
      const hexColorRegex = /^#[0-9A-Fa-f]{6}$/;
      
      CHART_COLORS.default.forEach((color) => {
        expect(color).toMatch(hexColorRegex);
      });
      
      Object.values(CHART_COLORS.status).forEach((color) => {
        expect(color).toMatch(hexColorRegex);
      });
      
      Object.values(CHART_COLORS.risk).forEach((color) => {
        expect(color).toMatch(hexColorRegex);
      });
      
      Object.values(CHART_COLORS.policy).forEach((color) => {
        expect(color).toMatch(hexColorRegex);
      });
    });
  });

  describe('DEFAULT_WIDGETS', () => {
    it('has default widget configurations', () => {
      expect(DEFAULT_WIDGETS).toBeDefined();
      expect(DEFAULT_WIDGETS.length).toBeGreaterThan(0);
    });

    it('each default widget has required properties', () => {
      DEFAULT_WIDGETS.forEach((widget) => {
        expect(widget.widgetType).toBeDefined();
        expect(widget.title).toBeDefined();
        expect(widget.position).toBeDefined();
      });
    });

    it('default widget positions are valid', () => {
      DEFAULT_WIDGETS.forEach((widget) => {
        if (widget.position) {
          expect(widget.position.x).toBeGreaterThanOrEqual(0);
          expect(widget.position.y).toBeGreaterThanOrEqual(0);
          expect(widget.position.w).toBeGreaterThan(0);
          expect(widget.position.h).toBeGreaterThan(0);
        }
      });
    });

    it('includes common dashboard widgets', () => {
      const widgetTypes = DEFAULT_WIDGETS.map((w) => w.widgetType);
      
      // Should include at least a KPI card and a chart
      expect(widgetTypes).toContain(WidgetType.KPI_CARD);
      expect(
        widgetTypes.some((t) => 
          t === WidgetType.PIE_CHART || 
          t === WidgetType.BAR_CHART || 
          t === WidgetType.LINE_CHART
        )
      ).toBe(true);
    });
  });
});




