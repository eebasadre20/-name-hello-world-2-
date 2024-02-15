import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Manager } from '../../entities/managers.ts'; // Corrected import path for Manager entity
import { ManagersService, ManagersEmailConfirmationService } from './managers.service';
import { ManagersController } from './managers.controller';
// AuthModule import removed as no authentication is required for the email confirmation endpoint

@Module({
  imports: [
    TypeOrmModule.forFeature([Manager]), // Keep the corrected Manager entity registration
    // AuthModule import removed as no authentication is required for the email confirmation endpoint
  ],
  providers: [
    ManagersService,
    ManagersEmailConfirmationService, // Keep the additional service from the existing code
  ],
  controllers: [ManagersController],
})
export class ManagersModule {}
