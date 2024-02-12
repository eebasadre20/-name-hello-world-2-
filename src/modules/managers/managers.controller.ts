import { Body, Controller, Post, BadRequestException } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { ManagersService } from './managers.service';
import { SignupManagerRequest, SignupManagerResponse } from './dto/signup-manager.dto';

@Controller('/api/managers')
@ApiTags('Managers')
export class ManagersController {
  constructor(private readonly managersService: ManagersService) {}

  @Post('/signup')
  async signup(@Body() request: SignupManagerRequest): Promise<SignupManagerResponse> {
    this.validateSignupRequest(request);
    return this.managersService.signupManager(request);
  }

  private validateSignupRequest(request: SignupManagerRequest): void {
    const { email, password, password_confirmation } = request;
    const passwordMinLength = 8; // Assuming this is the {{password_min_length}}
    const passwordRegex = new RegExp('^(?=.*[A-Za-z])(?=.*\\d)[A-Za-z\\d]{8,}$'); // Assuming this is the {{password_regex}}

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

    // Simple email validation
    if (!/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/.test(email)) {
      throw new BadRequestException('Email is invalid');
    }
  }
}
