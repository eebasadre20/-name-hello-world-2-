import {
  Body,
  Controller,
  Post,
  BadRequestException,
} from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { AdminUsersService } from './admin_users.service';

@Controller('admin_users')
@ApiTags('AdminUsers')
export class AdminUsersController {
  constructor(private readonly adminUsersService: AdminUsersService) {}

  @Post('/request-reset-password')
  async requestResetPassword(@Body() body: { email?: string }) {
    if (!body.email) {
      throw new BadRequestException('email is required');
    }
    const emailRegex = /\S+@\S+\.\S+/;
    if (!emailRegex.test(body.email)) {
      throw new BadRequestException('Email is invalid');
    }
    return this.adminUsersService.requestPasswordReset(body.email);
  }

  // ... other methods remain unchanged
}
