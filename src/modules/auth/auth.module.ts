import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { User } from 'src/entities/user.entity'; // Assuming User entity exists and is related to auth

@Module({
  imports: [TypeOrmModule.forFeature([User])], // Assuming User entity is related to authentication
  providers: [AuthService],
  controllers: [AuthController],
})
export class AuthModule {}
