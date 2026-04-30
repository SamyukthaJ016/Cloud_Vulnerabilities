import { Module } from '@nestjs/common';
import { TestProceduresController } from './test-procedures.controller';
import { TestProceduresService } from './test-procedures.service';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [TestProceduresController],
  providers: [TestProceduresService],
  exports: [TestProceduresService],
})
export class TestProceduresModule {}

