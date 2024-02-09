import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/entities/user.entity'; // Assuming the entity exists
import { UserService } from './user.service';
import { UserController } from './user.controller';

@Module({
  imports: [TypeOrmModule.forFeature([User])], // Assuming User entity is already defined
  providers: [UserService],
  controllers: [UserController],
})
export class UserModule {}
