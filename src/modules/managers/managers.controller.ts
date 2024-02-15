import {
  Body,
  HttpException,
  HttpStatus,
  Controller,
  Post,
  BadRequestException,
  HttpCode,
} from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { ManagersService } from './managers.service';
import { SignupManagerDto, SignupManagerResponse } from './dto/signup-manager.dto';
import { Manager } from '../../entities/managers';
import { ConfirmEmailRequest, ConfirmEmailResponse } from './dto/confirm-email.dto';
import { LoginRequest, LoginResponse } from './dto/login.dto';
import { RefreshTokenRequest, RefreshTokenResponse } from './dto/refresh-token.dto';
import { LogoutManagerRequest, LogoutManagerDto } from './dto/logout-manager.dto';
import { RequestPasswordResetDTO } from './dto/request-password-reset.dto';
import { ConfirmResetPasswordRequest, ConfirmResetPasswordResponse } from './dto/confirm-reset-password.dto';

@Controller('/api/managers')
@ApiTags('Managers')
export class ManagersController {
  private passwordMinLength = 8; // Assuming the password minimum length is 8
  private passwordRegex = new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)[a-zA-Z\\d]{8,}$'); // Assuming a regex pattern for password validation

  constructor(private readonly managersService: ManagersService) {}

  @Post('/signup')
  @HttpCode(HttpStatus.CREATED)
  async signup(@Body() signupManagerRequest: SignupManagerDto): Promise<SignupManagerResponse> {
    await this.validateSignupRequest(signupManagerRequest);
    const manager: Manager = await this.managersService.signupWithEmail(signupManagerRequest);
    return { user: manager };
  }

  private async validateSignupRequest(request: SignupManagerDto): Promise<void> {
    if (!request.email || !request.password || !request.passwordConfirmation) {
      throw new BadRequestException('email, password, and password_confirmation are required');
    }
    if (request.password !== request.passwordConfirmation) {
      throw new BadRequestException('Password confirmation does not match');
    }
    if (!request.name) {
      throw new BadRequestException('name is required');
    }
    if (!request.role) {
      throw new BadRequestException('role is required');
    }
    if (request.password.length < this.passwordMinLength) {
      throw new BadRequestException('Password is too short');
    }
    if (!this.passwordRegex.test(request.password)) {
      throw new BadRequestException('Password is invalid');
    }
  }

  @Post('/login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() loginRequest: LoginRequest): Promise<LoginResponse> {
    if (!loginRequest.email || !loginRequest.scope || !loginRequest.grant_type) {
      throw new BadRequestException('{field} is required');
    }
    if (loginRequest.grant_type === 'password' && (!loginRequest.password || loginRequest.password.length < this.passwordMinLength || !this.passwordRegex.test(loginRequest.password))) {
      throw new BadRequestException('Password is invalid');
    }
    if (loginRequest.grant_type === 'refresh_token' && !loginRequest.refresh_token) {
      throw new BadRequestException('refresh_token is required');
    }
    const loginResponse = await this.managersService.loginManager(loginRequest);
    return {
      access_token: loginResponse.access_token,
      refresh_token: loginResponse.refresh_token,
      resource_owner: loginResponse.resource_owner,
      resource_id: loginResponse.resource_id,
      expires_in: loginResponse.expires_in,
      token_type: loginResponse.token_type,
      scope: loginRequest.scope,
      created_at: loginResponse.created_at,
      refresh_token_expires_in: loginResponse.refresh_token_expires_in
    };
  }

  @Post('/refresh-token')
  async refreshToken(@Body() request: RefreshTokenRequest): Promise<RefreshTokenResponse> {
    this.validateRefreshTokenRequest(request);
    return this.managersService.refreshToken(request);
  }

  @Post('/logout')
  @HttpCode(HttpStatus.OK)
  async logout(@Body() logoutManagerRequest: LogoutManagerRequest | LogoutManagerDto) {
    if (!logoutManagerRequest.token) {
      throw new BadRequestException('token is required');
    }
    await this.managersService.logoutManager(logoutManagerRequest);
    return 'Logout successful'; // Assuming the service method handles both DTOs and returns a string
  }

  @Post('/confirm-email')
  @HttpCode(HttpStatus.OK)
  async confirmEmail(@Body() confirmEmailRequest: ConfirmEmailRequest): Promise<ConfirmEmailResponse> {
    if (!confirmEmailRequest || !confirmEmailRequest.token) {
      throw new BadRequestException('confirmation_token is required');
    }
    return this.managersService.confirmEmail(confirmEmailRequest);
  }

  private validateRefreshTokenRequest(request: RefreshTokenRequest): void {
    const { refresh_token, scope } = request;
    if (!refresh_token || !scope) {
      throw new BadRequestException(`${!refresh_token ? 'refresh_token' : 'scope'} is required`);
    }
  }
}
