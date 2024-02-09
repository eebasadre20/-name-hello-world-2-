import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ManagersService } from './managers.service';
import { ManagersController } from './managers.controller';
// Assuming Manager entity exists and is correctly implemented
import { Manager } from 'src/entities/manager';

@Module({
  imports: [TypeOrmModule.forFeature([Manager])],
  providers: [ManagersService],
  controllers: [ManagersController],
})
export class ManagersModule {}
