import { IsOptional, IsString, Matches, MaxLength, MinLength } from 'class-validator';

export class CreateOrganizationDto {
  @IsString()
  @MinLength(2)
  @MaxLength(80)
  name!: string;

  @IsString()
  @MinLength(2)
  @MaxLength(40)
  @Matches(/^[a-z0-9]+(-[a-z0-9]+)*$/, {
    message: 'slug must be lowercase alphanumeric with optional dashes (e.g. "acme-corp")',
  })
  slug!: string;

  @IsOptional()
  @IsString()
  @MaxLength(253)
  @Matches(/^[a-z0-9]+(\.[a-z0-9-]+)*\.[a-z]{2,}$/, {
    message: 'domain must be a bare hostname like "acme.com"',
  })
  domain?: string;
}
