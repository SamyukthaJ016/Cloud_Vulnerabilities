import { Module } from '@nestjs/common';
import { CallbackController } from './callback.controller';
import { CallbackHandlerService } from './callback-handler.service';
import { CallbackVerifierService } from './callback-verifier.service';

@Module({
  controllers: [CallbackController],
  providers: [CallbackHandlerService, CallbackVerifierService],
})
export class ScannerCallbacksModule {}
