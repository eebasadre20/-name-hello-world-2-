import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Manager } from '../../entities/managers'; // Corrected import path for Manager entity
import { ManagersService, ManagersEmailConfirmationService } from './managers.service';
import { ManagersController } from './managers.controller';
import { AuthModule } from '../auth/auth.module'; // Corrected relative import path for AuthModule

@Module({
  imports: [
    TypeOrmModule.forFeature([Manager]), // Keep the corrected Manager entity registration
    AuthModule, // Include AuthModule for authentication
  ],
  providers: [
    ManagersService,
    ManagersEmailConfirmationService, // Keep the additional service from the existing code
  ],
  controllers: [ManagersController],
})
export class ManagersModule {}
