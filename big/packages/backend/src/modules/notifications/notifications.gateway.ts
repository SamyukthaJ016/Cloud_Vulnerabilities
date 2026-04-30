import { OnGatewayConnection, OnGatewayDisconnect, WebSocketGateway } from '@nestjs/websockets';
import { Socket } from 'socket.io';
import { NotificationsService } from './notifications.service';

/**
 * WebSocket gateway for dashboard real-time updates (flow CQ: frontend polls / subscribes).
 *
 * Connection auth: the client connects with `?token=<jwt>`; gateway verifies and
 * attaches the user's `orgId` to the socket — outbound messages are filtered by orgId.
 */
@WebSocketGateway({
  namespace: '/ws',
  cors: {
    origin: true,
    credentials: true,
  },
})
export class NotificationsGateway implements OnGatewayConnection, OnGatewayDisconnect {
  constructor(private readonly notifications: NotificationsService) {
    // TODO: subscribe to internal events; forward to sockets in the matching org room
    //   notifications.on('scan.completed', (payload) => this.server.to(`org:${payload.orgId}`).emit(...))
  }

  async handleConnection(_client: Socket) {
    // TODO: verify JWT from handshake, attach orgId, join `org:<orgId>` room
  }

  async handleDisconnect(_client: Socket) {
    // TODO: cleanup
  }
}
