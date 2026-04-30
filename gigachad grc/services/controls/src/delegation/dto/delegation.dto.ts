import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsString, IsOptional, IsEnum, IsArray, IsDateString, IsInt, Min, Max } from 'class-validator';
import { Type } from 'class-transformer';

export enum DelegationScope {
  ALL = 'all',
  TASKS = 'tasks',
  APPROVALS = 'approvals',
  CONTROLS = 'controls',
  POLICIES = 'policies',
  RISKS = 'risks',
}

export enum DelegationStatus {
  PENDING = 'pending',
  ACTIVE = 'active',
  EXPIRED = 'expired',
  REVOKED = 'revoked',
}

export class CreateDelegationDto {
  @ApiProperty({ description: 'User ID to delegate to' })
  @IsString()
  delegateeId: string;

  @ApiProperty({ description: 'Start date of delegation' })
  @IsDateString()
  startDate: string;

  @ApiProperty({ description: 'End date of delegation' })
  @IsDateString()
  endDate: string;

  @ApiPropertyOptional({ 
    description: 'Scopes to delegate',
    enum: DelegationScope,
    isArray: true,
    default: [DelegationScope.ALL],
  })
  @IsOptional()
  @IsArray()
  @IsEnum(DelegationScope, { each: true })
  scopes?: DelegationScope[] = [DelegationScope.ALL];

  @ApiPropertyOptional({ description: 'Notes about the delegation' })
  @IsOptional()
  @IsString()
  notes?: string;
}

export class UpdateDelegationDto {
  @ApiPropertyOptional()
  @IsOptional()
  @IsDateString()
  endDate?: string;

  @ApiPropertyOptional({ enum: DelegationScope, isArray: true })
  @IsOptional()
  @IsArray()
  @IsEnum(DelegationScope, { each: true })
  scopes?: DelegationScope[];

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  notes?: string;
}

export class DelegationDto {
  @ApiProperty()
  id: string;

  @ApiProperty()
  delegatorId: string;

  @ApiProperty()
  delegatorName: string;

  @ApiProperty()
  delegatorEmail: string;

  @ApiProperty()
  delegateeId: string;

  @ApiProperty()
  delegateeName: string;

  @ApiProperty()
  delegateeEmail: string;

  @ApiProperty()
  startDate: Date;

  @ApiProperty()
  endDate: Date;

  @ApiProperty({ enum: DelegationScope, isArray: true })
  scopes: DelegationScope[];

  @ApiProperty({ enum: DelegationStatus })
  status: DelegationStatus;

  @ApiPropertyOptional()
  notes?: string;

  @ApiProperty()
  createdAt: Date;

  @ApiProperty()
  updatedAt: Date;
}

export class DelegationListQueryDto {
  @ApiPropertyOptional({ enum: DelegationStatus })
  @IsOptional()
  @IsEnum(DelegationStatus)
  status?: DelegationStatus;

  @ApiPropertyOptional({ description: 'Show delegations where I am the delegator' })
  @IsOptional()
  asDelegator?: boolean;

  @ApiPropertyOptional({ description: 'Show delegations where I am the delegatee' })
  @IsOptional()
  asDelegatee?: boolean;

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

export class ActiveDelegationsDto {
  @ApiProperty({ description: 'Delegations where I am delegating to others' })
  outgoing: DelegationDto[];

  @ApiProperty({ description: 'Delegations where others are delegating to me' })
  incoming: DelegationDto[];
}
