import { Body, Controller, Post, BadRequestException } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { ManagersService } from './managers.service';
import { SignupManagerRequest, SignupManagerResponse } from './dto/signup-manager.dto';
import { ConfirmEmailRequest, ConfirmEmailResponse } from './dto/confirm-email.dto';

@Controller('/api/managers')
@ApiTags('Managers')
export class ManagersController {
  constructor(private readonly managersService: ManagersService) {}

  @Post('/signup')
  async signupWithEmail(@Body() request: SignupManagerRequest): Promise<SignupManagerResponse> {
    this.validateSignupRequest(request);
    return this.managersService.signupWithEmail(request);
  }

  @Post('/confirm-email')
  async confirmEmail(@Body() body: { confirmation_token: string }): Promise<ConfirmEmailResponse> {
    if (!body.confirmation_token) {
      throw new BadRequestException('confirmation_token is required');
    }
    const request: ConfirmEmailRequest = { token: body.confirmation_token };
    return this.managersService.confirmEmail(request);
  }

  private validateSignupRequest(request: SignupManagerRequest): void {
    const { email, password, password_confirmation } = request;
    const passwordMinLength = 8; // Assuming 8 is the minimum length, replace with actual value if different
    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/; // Example regex, replace with actual regex if different

    if (!email || !password || !password_confirmation) {
      throw new BadRequestException(`${!email ? 'Email' : !password ? 'Password' : 'Password confirmation'} is required`);
    }

    if (password !== password_confirmation) {
      throw new BadRequestException('Password confirmation does not match');
    }

    if (password.length < passwordMinLength) {
      throw new BadRequestException('Password is invalid');
    }

    if (!passwordRegex.test(password)) {
      throw new BadRequestException('Password is invalid');
    }

    // Assuming a simple regex for email validation, replace with a more complex one if needed
    if (!/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/.test(email)) {
      throw new BadRequestException('Email is invalid');
    }
  }
}
