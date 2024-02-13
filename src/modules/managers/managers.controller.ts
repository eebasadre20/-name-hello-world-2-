import {
  Body,
  Controller,
  Post,
  BadRequestException,
} from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { ManagersService } from './managers.service';
import { LoginRequest, LoginResponse } from './dto/login.dto';
import { RefreshTokenRequest, RefreshTokenResponse } from './dto/refresh-token.dto';
import { LogoutManagerRequest } from './dto/logout-manager.dto';

@Controller('/api/managers')
@ApiTags('Managers')
export class ManagersController {
  constructor(private readonly managersService: ManagersService) {}

  @Post('/login')
  async login(@Body() body: any): Promise<LoginResponse | RefreshTokenResponse> {
    const { email, password, grant_type, client_id, client_secret, refresh_token, scope } = body;

    // Required fields validation
    if (!email) throw new BadRequestException('email is required');
    if (!scope) throw new BadRequestException('scope is required');
    if (!grant_type) throw new BadRequestException('grant_type is required');

    // Grant type specific validations
    if (grant_type === 'password') {
      if (!password) throw new BadRequestException('password is required');
      // Assuming password_min_length and password_regex are available in the environment or config
      const passwordMinLength = parseInt(process.env.PASSWORD_MIN_LENGTH || '8');
      const passwordRegex = new RegExp(process.env.PASSWORD_REGEX || '^(?=.*[A-Za-z])(?=.*\\d)[A-Za-z\\d]{8,}$');
      if (password.length < passwordMinLength || !passwordRegex.test(password)) {
        throw new BadRequestException('Password is invalid');
      }
      const loginRequest: LoginRequest = { email, password, client_id, client_secret, scope };
      return this.managersService.loginManager(loginRequest);
    } else if (grant_type === 'refresh_token') {
      if (!refresh_token) throw new BadRequestException('refresh_token is required');
      const refreshTokenRequest: RefreshTokenRequest = { refresh_token, scope, client_id, client_secret };
      return this.managersService.refreshToken(refreshTokenRequest);
    } else {
      throw new BadRequestException('Invalid grant_type');
    }
  }

  @Post('/logout')
  async logout(@Body() logoutManagerRequest: LogoutManagerRequest): Promise<void> {
    if (!logoutManagerRequest.token) {
      throw new BadRequestException('token is required');
    }
    await this.managersService.logoutManager(logoutManagerRequest);
  }
}
