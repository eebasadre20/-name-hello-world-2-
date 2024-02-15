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
import { LogoutManagerDto } from './dto/logout-manager.dto';
import { ManagersService } from './managers.service';
import { SignupManagerDto, SignupManagerResponse } from './dto/signup-manager.dto'; // Use SignupManagerDto from new code
import { ConfirmEmailRequest, ConfirmEmailResponse } from './dto/confirm-email.dto';
import { LoginRequest, LoginResponse } from './dto/login.dto';
import { RefreshTokenRequest, RefreshTokenResponse } from './dto/refresh-token.dto';
import { Manager } from '../../entities/managers';
import { LogoutManagerRequest } from './dto/logout-manager.dto';

@Controller('/api/managers')
@ApiTags('Managers')
export class ManagersController {
  constructor(private readonly managersService: ManagersService) {}

  @Post('/signup')
  @HttpCode(HttpStatus.CREATED) // Use HttpStatus.CREATED from new code
  async signup(@Body() signupManagerRequest: SignupManagerDto): Promise<SignupManagerResponse> { // Use SignupManagerDto from new code
    await this.validateSignupRequest(signupManagerRequest);
    const manager: Manager = await this.managersService.signupWithEmail(signupManagerRequest);
    return { user: manager };
  }

  private async validateSignupRequest(request: SignupManagerDto): Promise<void> { // Use SignupManagerDto from new code
    if (!request.email || !request.password || !request.passwordConfirmation) { // Use passwordConfirmation from new code
      throw new BadRequestException('email, password, and password_confirmation are required');
    }
    if (request.password !== request.passwordConfirmation) { // Use passwordConfirmation from new code
      throw new BadRequestException('Password confirmation does not match');
    }
    // Additional required fields validation
    if (!request.name) {
      throw new BadRequestException('name is required');
    }
    if (!request.role) {
      throw new BadRequestException('role is required');
    }
    if (!new RegExp(request.password_regex).test(request.password)) {
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

  @Post('/logout')
  async logout(@Body() logoutManagerDto: LogoutManagerDto) {
    if (!logoutManagerDto.token) {
      throw new BadRequestException('token is required');
    }
    await this.managersService.logoutManager(logoutManagerDto);
    return { message: 'Logout successful' };
  }

  @Post('/confirm-email')
  @HttpCode(200)
  async confirmEmail(@Body() confirmEmailRequest: ConfirmEmailRequest): Promise<ConfirmEmailResponse> {
    if (!confirmEmailRequest || !confirmEmailRequest.token) { // Use token from new code
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
