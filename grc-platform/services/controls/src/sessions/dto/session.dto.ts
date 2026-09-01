import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsString, IsOptional, IsBoolean, IsInt, Min, Max } from 'class-validator';
import { Type } from 'class-transformer';

export class SessionDto {
  @ApiProperty()
  id: string;

  @ApiProperty()
  userId: string;

  @ApiProperty()
  deviceInfo: string;

  @ApiProperty()
  browser: string;

  @ApiProperty()
  os: string;

  @ApiProperty()
  ipAddress: string;

  @ApiProperty()
  location?: string;

  @ApiProperty()
  isActive: boolean;

  @ApiProperty()
  isCurrent: boolean;

  @ApiProperty()
  createdAt: Date;

  @ApiProperty()
  lastActivityAt: Date;

  @ApiProperty()
  expiresAt: Date;
}

export class SessionListQueryDto {
  @ApiPropertyOptional({ default: false })
  @IsOptional()
  @IsBoolean()
  activeOnly?: boolean = false;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  userId?: string;

  @ApiPropertyOptional({ default: 1 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page?: number = 1;

  @ApiPropertyOptional({ default: 20 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  limit?: number = 20;
}

export class InvalidateSessionDto {
  @ApiPropertyOptional({ description: 'Reason for invalidating the session' })
  @IsOptional()
  @IsString()
  reason?: string;
}

export class SessionStatsDto {
  @ApiProperty()
  totalActiveSessions: number;

  @ApiProperty()
  uniqueUsers: number;

  @ApiProperty()
  sessionsToday: number;

  @ApiProperty()
  sessionsThisWeek: number;

  @ApiProperty({ type: [Object] })
  browserDistribution: { browser: string; count: number }[];

  @ApiProperty({ type: [Object] })
  osDistribution: { os: string; count: number }[];
}

export class SessionSettingsDto {
  @ApiProperty({ description: 'Session timeout in minutes' })
  sessionTimeoutMinutes: number;

  @ApiProperty({ description: 'Maximum concurrent sessions per user' })
  maxConcurrentSessions: number;

  @ApiProperty({ description: 'Whether to enforce single session' })
  enforceSingleSession: boolean;

  @ApiProperty({ description: 'Whether to require re-auth for sensitive actions' })
  requireReauthForSensitiveActions: boolean;
}

export class UpdateSessionSettingsDto {
  @ApiPropertyOptional()
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(5)
  @Max(10080) // Max 1 week
  sessionTimeoutMinutes?: number;

  @ApiPropertyOptional()
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  maxConcurrentSessions?: number;

  @ApiPropertyOptional()
  @IsOptional()
  @IsBoolean()
  enforceSingleSession?: boolean;

  @ApiPropertyOptional()
  @IsOptional()
  @IsBoolean()
  requireReauthForSensitiveActions?: boolean;
}
