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
import { ConfirmEmailRequest, ConfirmEmailResponse } from './dto/confirm-email.dto';
import { LoginRequest, LoginResponse } from './dto/login.dto';
import { RefreshTokenRequest, RefreshTokenResponse } from './dto/refresh-token.dto';
import { Manager } from '../../entities/managers';
import { LogoutManagerRequest, LogoutManagerDto } from './dto/logout-manager.dto';
import { RequestPasswordResetDTO } from './dto/request-password-reset.dto'; // Added import for RequestPasswordResetDTO
import { ConfirmResetPasswordRequest, ConfirmResetPasswordResponse } from './dto/confirm-reset-password.dto'; // Added import for ConfirmResetPasswordDTO

@Controller('/api/managers')
@ApiTags('Managers')
export class ManagersController {
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
    if (!new RegExp(request.password_regex).test(request.password)) {
      throw new BadRequestException('Password is invalid');
    }
  }

  @Post('/login')
  async login(@Body() request: LoginRequest): Promise<LoginResponse> {
    this.validateLoginRequest(request);
    const loginResponse = await this.managersService.loginManager(request);
    return {
      access_token: loginResponse.access_token,
      refresh_token: loginResponse.refresh_token,
      resource_owner: loginResponse.resource_owner,
      resource_id: loginResponse.resource_id,
      expires_in: loginResponse.expires_in,
      token_type: loginResponse.token_type,
      scope: request.scope,
      created_at: loginResponse.created_at,
      refresh_token_expires_in: loginResponse.refresh_token_expires_in
    };
  }

  @Post('/refresh-token')
  async refreshToken(@Body() request: RefreshTokenRequest): Promise<RefreshTokenResponse> {
    this.validateRefreshTokenRequest(request);
    return this.managersService.refreshToken(request);
  }

  @Post('/confirm-reset-password')
  @HttpCode(HttpStatus.OK)
  async confirmResetPassword(@Body() confirmResetPasswordRequest: ConfirmResetPasswordRequest): Promise<ConfirmResetPasswordResponse> {
    if (!confirmResetPasswordRequest.reset_token || !confirmResetPasswordRequest.password || !confirmResetPasswordRequest.password_confirmation) {
      throw new BadRequestException('reset_token, password, and password_confirmation are required');
    }
    if (confirmResetPasswordRequest.password !== confirmResetPasswordRequest.password_confirmation) {
      throw new BadRequestException('Password confirmation does not match');
    }
    if (confirmResetPasswordRequest.password.length < this.managersService.getPasswordMinLength()) {
      throw new BadRequestException('Password is invalid');
    }
    if (!new RegExp(this.managersService.getPasswordRegex()).test(confirmResetPasswordRequest.password)) {
      throw new BadRequestException('Password is invalid');
    }
    return this.managersService.confirmResetPassword(confirmResetPasswordRequest);
  }

  @Post('/logout')
  async logout(@Body() logoutManagerRequest: LogoutManagerRequest | LogoutManagerDto) {
    if (!logoutManagerRequest.token) {
      throw new BadRequestException('token is required');
    }
    await this.managersService.logoutManager(logoutManagerRequest);
    return 'Logout successful'; // Assuming the service method handles both DTOs and returns a string
  }

  @Post('/confirm-email')
  @HttpCode(200)
  async confirmEmail(@Body() confirmEmailRequest: ConfirmEmailRequest): Promise<ConfirmEmailResponse> {
    if (!confirmEmailRequest || !confirmEmailRequest.token) {
      throw new BadRequestException('confirmation_token is required');
    }
    return this.managersService.confirmEmail(confirmEmailRequest);
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

  @Post('/reset-password-request')
  @HttpCode(HttpStatus.OK)
  async requestPasswordReset(@Body() requestPasswordResetDto: RequestPasswordResetDTO): Promise<{ message: string }> {
    if (!requestPasswordResetDto.email) {
      throw new BadRequestException('email is required');
    }
    if (!/^\S+@\S+\.\S+$/.test(requestPasswordResetDto.email)) {
      throw new BadRequestException('Email is invalid');
    }
    try {
      await this.managersService.requestPasswordReset(requestPasswordResetDto.email);
      return { message: 'Password reset request processed successfully.' };
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.BAD_REQUEST);
    }
  }
}
