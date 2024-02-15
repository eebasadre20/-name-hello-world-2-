import {
  Body,
  Controller,
  Post,
  BadRequestException,
  HttpCode,
} from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { ManagersService } from './managers.service';
import { ConfirmEmailRequest, ConfirmEmailResponse } from './dto/confirm-email.dto';
import { LoginRequest, LoginResponse } from './dto/login.dto';
import { SignupManagerRequest, SignupManagerResponse } from './dto/signup-manager.dto';
import { RefreshTokenRequest, RefreshTokenResponse } from './dto/refresh-token.dto';
import { Manager } from '../../entities/managers'; // Added import for Manager entity
import { LogoutManagerRequest } from './dto/logout-manager.dto';

@Controller('/api/managers')
@ApiTags('Managers')
export class ManagersController {
  constructor(private readonly managersService: ManagersService) {}

  @Post('/signup')
  @HttpCode(200) // Changed from 201 to 200 to match the new code
  async signup(@Body() signupManagerRequest: SignupManagerRequest): Promise<SignupManagerResponse> {
    await this.validateSignupRequest(signupManagerRequest); // Changed to async to match the new code
    const manager: Manager = await this.managersService.signupWithEmail(signupManagerRequest); // Added type Manager to match the new code
    return { user: manager }; // Changed to return an object with user property to match the new code
  }

  private async validateSignupRequest(request: SignupManagerRequest): Promise<void> { // Changed to async to match the new code
    if (!request.email || !request.password || !request.password_confirmation) {
      throw new BadRequestException('email, password, and password_confirmation are required');
    }
    if (request.password !== request.password_confirmation) {
      throw new BadRequestException('Password confirmation does not match');
    }
    // Additional required fields validation
    // Assuming other required fields are 'name' and 'role'
    if (!request.name) {
      throw new BadRequestException('name is required');
    }
    if (!request.role) {
      throw new BadRequestException('role is required');
    }
    if (!new RegExp(request.password_regex).test(request.password)) { // Added password regex validation to match the new code
      throw new BadRequestException('Password is invalid');
    }
    // Additional validation logic can be added here
  }

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
}
