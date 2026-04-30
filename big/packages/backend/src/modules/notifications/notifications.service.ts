import { Injectable } from '@nestjs/common';
import { EventEmitter } from 'events';

/**
 * Internal event bus for dashboard refresh + real-time updates.
 * Flow node Q1 (internal side).
 *
 * Other modules call `emit(event, payload)`. The NotificationsGateway
 * subscribes and pushes to connected WebSocket clients scoped by org.
 */
@Injectable()
export class NotificationsService {
  private readonly bus = new EventEmitter();

  emit<T>(event: NotificationEvent, payload: T): void {
    this.bus.emit(event, payload);
  }

  on<T>(event: NotificationEvent, handler: (payload: T) => void): void {
    this.bus.on(event, handler);
  }
}

export type NotificationEvent =
  | 'scan.dispatched'
  | 'scan.completed'
  | 'scan.failed'
  | 'finding.created'
  | 'billing.updated'
  | 'secret.changed';
