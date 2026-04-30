import { useCallback, useMemo } from 'react';
import GridLayout, { Layout } from 'react-grid-layout';
import 'react-grid-layout/css/styles.css';
import 'react-resizable/css/styles.css';
import { DashboardWidget, WIDGET_TYPES } from '@/lib/dashboardWidgets';
import WidgetContainer from './WidgetContainer';

interface DashboardGridProps {
  widgets: DashboardWidget[];
  isEditing: boolean;
  onLayoutChange: (layout: Layout[]) => void;
  onWidgetEdit: (widget: DashboardWidget) => void;
  onWidgetDelete: (widgetId: string) => void;
  onWidgetRefresh: (widgetId: string) => void;
  dashboardId: string;
}

export default function DashboardGrid({
  widgets,
  isEditing,
  onLayoutChange,
  onWidgetEdit,
  onWidgetDelete,
  onWidgetRefresh,
  dashboardId,
}: DashboardGridProps) {
  // Convert widgets to grid layout format
  const layout: Layout[] = useMemo(() => {
    return widgets.map((widget) => ({
      i: widget.id,
      x: widget.position.x,
      y: widget.position.y,
      w: widget.position.w,
      h: widget.position.h,
      minW: WIDGET_TYPES[widget.widgetType]?.minSize.w || 2,
      minH: WIDGET_TYPES[widget.widgetType]?.minSize.h || 1,
      maxW: WIDGET_TYPES[widget.widgetType]?.maxSize.w || 12,
      maxH: WIDGET_TYPES[widget.widgetType]?.maxSize.h || 8,
      static: !isEditing,
    }));
  }, [widgets, isEditing]);

  const handleLayoutChange = useCallback(
    (newLayout: Layout[]) => {
      if (isEditing) {
        onLayoutChange(newLayout);
      }
    },
    [isEditing, onLayoutChange]
  );

  return (
    <div className="dashboard-grid">
      <GridLayout
        className="layout"
        layout={layout}
        cols={12}
        rowHeight={80}
        width={1200}
        onLayoutChange={handleLayoutChange}
        isDraggable={isEditing}
        isResizable={isEditing}
        compactType="vertical"
        preventCollision={false}
        margin={[16, 16]}
        containerPadding={[0, 0]}
        useCSSTransforms={true}
        draggableHandle=".widget-drag-handle"
      >
        {widgets.map((widget) => (
          <div key={widget.id}>
            <WidgetContainer
              widget={widget}
              dashboardId={dashboardId}
              isEditing={isEditing}
              onEdit={() => onWidgetEdit(widget)}
              onDelete={() => onWidgetDelete(widget.id)}
              onRefresh={() => onWidgetRefresh(widget.id)}
            />
          </div>
        ))}
      </GridLayout>
    </div>
  );
}




