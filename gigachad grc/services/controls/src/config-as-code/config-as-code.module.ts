import { Module } from '@nestjs/common';
import { ConfigAsCodeController } from './config-as-code.controller';
import { ConfigAsCodeService } from './config-as-code.service';
import { ConfigFilesController } from './config-files.controller';
import { ConfigFilesService } from './config-files.service';
import { ConfigStateService } from './state/config-state.service';
import { ResourceMapper } from './resources/resource-mapper';
import { YamlExporter } from './exporters/yaml-exporter';
import { JsonExporter } from './exporters/json-exporter';
import { TerraformExporter } from './exporters/terraform-exporter';

@Module({
  controllers: [ConfigAsCodeController, ConfigFilesController],
  providers: [
    ConfigAsCodeService,
    ConfigFilesService,
    ConfigStateService,
    ResourceMapper,
    YamlExporter,
    JsonExporter,
    TerraformExporter,
  ],
  exports: [ConfigAsCodeService, ConfigFilesService, ConfigStateService],
})
export class ConfigAsCodeModule {}

