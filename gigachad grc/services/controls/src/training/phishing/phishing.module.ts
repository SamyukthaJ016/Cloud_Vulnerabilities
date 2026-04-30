import { Module } from '@nestjs/common';
import { PhishingController } from './phishing.controller';
import { PhishingService } from './phishing.service';
import { PrismaModule } from '../../prisma/prisma.module';
import { EmailModule } from '../../email/email.module';

@Module({
  imports: [PrismaModule, EmailModule],
  controllers: [PhishingController],
  providers: [PhishingService],
  exports: [PhishingService],
})
export class PhishingModule {}

