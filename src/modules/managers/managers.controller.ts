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
  async login(@Body() request: LoginRequest): Promise<LoginResponse> {
    this.validateLoginRequest(request);
    return this.managersService.loginManager(request);
  }

  @Post('/refresh-token')
  async refreshToken(@Body() request: RefreshTokenRequest): Promise<RefreshTokenResponse> {
    this.validateRefreshTokenRequest(request);
    return this.managersService.refreshToken(request);
  }

  @Post('/logout')
  async logout(@Body() logoutManagerRequest: LogoutManagerRequest) {
    if (!logoutManagerRequest.token) {
      throw new BadRequestException('token is required');
    }
    return this.managersService.logoutManager(logoutManagerRequest);
  }

  private validateLoginRequest(request: LoginRequest): void {
    const { email, password, grant_type, scope } = request;
    if (!email || !scope || !grant_type) {
      throw new BadRequestException(`${!email ? 'email' : !scope ? 'scope' : 'grant_type'} is required`);
    }
    if (grant_type === 'password' && !password) {
      throw new BadRequestException('password is required');
    }
    if (grant_type === 'refresh_token' && !request.refresh_token) {
      throw new BadRequestException('refresh_token is required');
    }
  }

  private validateRefreshTokenRequest(request: RefreshTokenRequest): void {
    const { refresh_token, scope } = request;
    if (!refresh_token || !scope) {
      throw new BadRequestException(`${!refresh_token ? 'refresh_token' : 'scope'} is required`);
    }
  }
}
