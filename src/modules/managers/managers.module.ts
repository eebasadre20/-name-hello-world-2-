import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Manager } from '../../entities/managers.ts'; // Corrected import path for Manager entity
import { ManagersService, ManagersEmailConfirmationService } from './managers.service';
import { ManagersController } from './managers.controller';
import { AuthModule } from 'src/auth/auth.module'; // Keep the AuthModule import from the existing code

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
