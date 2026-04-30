import { Module } from '@nestjs/common';
import { BillingController } from './billing.controller';
import { BillingService } from './billing.service';
import { RazorpayClient } from './razorpay/razorpay.client';
import { RazorpayService } from './razorpay/razorpay.service';
import { PlansModule } from '../plans/plans.module';

@Module({
  imports: [PlansModule],
  controllers: [BillingController],
  providers: [BillingService, RazorpayClient, RazorpayService],
  exports: [BillingService, RazorpayService, RazorpayClient],
})
export class BillingModule {}
