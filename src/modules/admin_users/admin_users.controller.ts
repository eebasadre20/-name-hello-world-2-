import {
  Body,
  Controller,
  Post,
  BadRequestException,
} from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { AdminUsersService } from './admin_users.service';
import { LoginRequest, LoginResponse } from './dto/login.dto';
import { RefreshTokenRequest, RefreshTokenResponse } from './dto/refresh-token.dto';
import { LogoutAdminUserRequest } from './dto/logout-admin-user.dto';

@Controller('admin_users')
@ApiTags('AdminUsers')
export class AdminUsersController {
  constructor(private readonly adminUsersService: AdminUsersService) {}

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
      // Assuming password_min_length and password_regex are defined elsewhere
      const password_min_length = 8; // Example minimum length
      const password_regex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/; // Example regex
      if (password.length < password_min_length) throw new BadRequestException('Password is invalid');
      if (!password_regex.test(password)) throw new BadRequestException('Password is invalid');

      const loginRequest: LoginRequest = { email, password };
      return this.adminUsersService.emailLogin(loginRequest);
    } else if (grant_type === 'refresh_token') {
      if (!refresh_token) throw new BadRequestException('refresh_token is required');

      const refreshTokenRequest: RefreshTokenRequest = { refresh_token, scope };
      return this.adminUsersService.refreshToken(refreshTokenRequest);
    } else {
      throw new BadRequestException('Invalid grant_type');
    }
  }

  @Post('logout')
  async logoutAdminUser(@Body() logoutAdminUserRequest: LogoutAdminUserRequest) {
    if (!logoutAdminUserRequest.token) {
      throw new BadRequestException('token is required');
    }
    return this.adminUsersService.logoutAdminUser(logoutAdminUserRequest);
  }

  // ... other existing controller methods
}
