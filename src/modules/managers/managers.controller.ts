import {
  Body,
  Controller,
  Post,
  BadRequestException,
} from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { ManagersService } from './managers.service';
import { ConfirmResetPasswordRequest } from './dto/confirm-reset-password.dto';

@Controller('/api/managers')
@ApiTags('Managers')
export class ManagersController {
  constructor(private readonly managersService: ManagersService) {}

  @Post('/reset-password-confirm')
  async confirmResetPassword(@Body() body: ConfirmResetPasswordRequest) {
    const { reset_token, password, password_confirmation } = body;

    // Validation
    if (!reset_token || !password || !password_confirmation) {
      let missingFields = [];
      if (!reset_token) missingFields.push('reset_token');
      if (!password) missingFields.push('password');
      if (!password_confirmation) missingFields.push('password_confirmation');
      throw new BadRequestException(`${missingFields.join(', ')} is required`);
    }

    if (password !== password_confirmation) {
      throw new BadRequestException('Password confirmation does not match');
    }

    const passwordMinLength = parseInt(process.env.PASSWORD_MIN_LENGTH || '8');
    if (password.length < passwordMinLength) {
      throw new BadRequestException('Password is invalid');
    }

    const passwordRegex = new RegExp(process.env.PASSWORD_REGEX || '^(?=.*[A-Za-z])(?=.*\\d)[A-Za-z\\d]{8,}$');
    if (!passwordRegex.test(password)) {
      throw new BadRequestException('Password is invalid');
    }

    return this.managersService.confirmResetPassword({ token: reset_token, password });
  }

  // ... other controller methods
}
