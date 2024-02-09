import { Body, Controller, Post, BadRequestException, HttpException, HttpStatus } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { ManagersService } from './managers.service';
import { SignupManagerRequest, SignupManagerResponse } from './dto/signup-manager.dto';
import { ConfirmEmailRequest } from './dto/confirm-email.dto'; // Assuming the DTO exists

@Controller('/api/managers')
@ApiTags('Managers')
export class ManagersController {
  constructor(private readonly managersService: ManagersService) {}

  @Post('/signup')
  async signup(@Body() request: SignupManagerRequest): Promise<SignupManagerResponse> {
    this.validateSignupRequest(request);
    return this.managersService.signupManager(request);
  }

  @Post('/confirm-email')
  async confirmEmail(@Body() request: ConfirmEmailRequest) {
    if (!request.confirmation_token) {
      throw new HttpException('confirmation_token is required', HttpStatus.BAD_REQUEST);
    }
    const result = await this.managersService.confirmEmail(request.confirmation_token);
    return result; // Assuming the service method returns the appropriate response
  }

  private validateSignupRequest(request: SignupManagerRequest): void {
    const { email, password, password_confirmation } = request;
    const passwordMinLength = 8; // Assuming password_min_length is 8
    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/; // Assuming a regex pattern for password

    if (!email || !password || !password_confirmation) {
      throw new BadRequestException(`${!email ? 'Email' : !password ? 'Password' : 'Password confirmation'} is required`);
    }

    if (password.length < passwordMinLength) {
      throw new BadRequestException('Password is invalid');
    }

    if (!passwordRegex.test(password)) {
      throw new BadRequestException('Password is invalid');
    }

    if (password !== password_confirmation) {
      throw new BadRequestException('Password confirmation does not match');
    }

    // Assuming a simple regex for validating email format
    if (!/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/.test(email)) {
      throw new BadRequestException('Email is invalid');
    }
  }
}
