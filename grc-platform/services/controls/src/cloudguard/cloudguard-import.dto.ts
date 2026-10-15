import { IsInt, Min } from 'class-validator';

export class ImportCloudGuardScanDto {
  @IsInt()
  @Min(1)
  scanId: number;
}
