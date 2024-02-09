import {
  Body,
  Controller,
  Post,
  BadRequestException,
} from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { ConfirmResetPasswordRequest, SuccessResponse } from './dto';
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

  @Post('/reset-password-confirm')
  async confirmResetPassword(@Body() body: ConfirmResetPasswordRequest): Promise<SuccessResponse> {
    const { reset_token, password, password_confirmation } = body;

    // Validation
    if (!reset_token || !password || !password_confirmation) {
      throw new BadRequestException(`${!reset_token ? 'reset_token' : !password ? 'password' : 'password_confirmation'} is required`);
    }

    if (password !== password_confirmation) {
      throw new BadRequestException('Password confirmation does not match');
    }

    const passwordMinLength = 8; // Assuming password_min_length is 8
    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/; // Assuming password_regex is this

    if (password.length < passwordMinLength || !passwordRegex.test(password)) {
      throw new BadRequestException('Password is invalid');
    }

    return this.adminUsersService.confirmResetPassword({ token: reset_token, password });
  }
}
