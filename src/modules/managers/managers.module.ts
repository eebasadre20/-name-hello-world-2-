import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Manager } from 'src/entities/managers';
import { ManagersService, ManagersEmailConfirmationService } from './managers.service';
import { ManagersController } from './managers.controller';
import { AuthModule } from 'src/auth/auth.module'; // Import the AuthModule

@Module({
  imports: [TypeOrmModule.forFeature([Manager]), AuthModule], // Include AuthModule for authentication
  providers: [
    ManagersService,
    ManagersEmailConfirmationService, // Keep the additional service from the existing code
  ],
  controllers: [ManagersController],
})
export class ManagersModule {}
