import { Module } from '@nestjs/common';
import { QuestionnairesService } from './questionnaires.service';
import { QuestionnairesController } from './questionnaires.controller';
import { SimilarQuestionsService } from './similar-questions.service';
import { QuestionnaireExportService } from './export.service';
import { PrismaService } from '../common/prisma.service';
import { AuditService } from '../common/audit.service';

@Module({
  controllers: [QuestionnairesController],
  providers: [QuestionnairesService, SimilarQuestionsService, QuestionnaireExportService, PrismaService, AuditService],
  exports: [QuestionnairesService, SimilarQuestionsService, QuestionnaireExportService],
})
export class QuestionnairesModule {}
