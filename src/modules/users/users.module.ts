import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/entities/user.entity'; // Assuming User entity exists
import { UsersService } from './users.service';
import { UsersController } from './users.controller';

@Module({
  imports: [TypeOrmModule.forFeature([User])], // Assuming User entity is correctly imported
  providers: [UsersService], // Provide the UsersService
  controllers: [UsersController], // Provide the UsersController
})
export class UsersModule {}
