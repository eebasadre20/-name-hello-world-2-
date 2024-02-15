import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Manager } from '../../entities/managers';
import { ManagersService, ManagersEmailConfirmationService } from './managers.service';
import { ManagersController } from './managers.controller';
import { AuthModule } from 'src/auth/auth.module'; // Keep the AuthModule import for authentication

@Module({
  imports: [
    TypeOrmModule.forFeature([Manager]),
    AuthModule, // Include AuthModule for authentication purposes
  ],
  providers: [
    ManagersService,
    ManagersEmailConfirmationService, // Include both services
  ],
  controllers: [ManagersController],
})
export class ManagersModule {}
