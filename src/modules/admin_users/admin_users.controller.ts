import { Body, Controller, Post, BadRequestException } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { AdminUsersService } from './admin_users.service';
import { RegisterAdminUserRequest, RegisterAdminUserResponse } from './dto/register-admin-user.dto';

@Controller('admin_users')
@ApiTags('AdminUsers')
export class AdminUsersController {
  constructor(private readonly adminUsersService: AdminUsersService) {}

  @Post('signup')
  async signupWithEmail(@Body() body: any): Promise<RegisterAdminUserResponse> {
    const { admin_users } = body;
    if (!admin_users) {
      throw new BadRequestException('admin_users object is required');
    }
    const { email, password, password_confirmation } = admin_users;

    // Validation
    if (!email) {
      throw new BadRequestException('Email is required');
    }
    if (!password) {
      throw new BadRequestException('Password is required');
    }
    if (!password_confirmation) {
      throw new BadRequestException('Password confirmation is required');
    }
    if (password !== password_confirmation) {
      throw new BadRequestException('Password confirmation does not match');
    }
    const passwordRegex = new RegExp(admin_users.password_regex);
    if (password.length < admin_users.password_min_length || !passwordRegex.test(password)) {
      throw new BadRequestException('Password is invalid');
    }
    // Assuming a utility function for email validation
    if (!this.validateEmail(email)) {
      throw new BadRequestException('Email is invalid');
    }

    const requestDto = new RegisterAdminUserRequest();
    requestDto.email = email;
    requestDto.password = password;

    const newUser = await this.adminUsersService.signupWithEmail(requestDto);
    return { admin_users: { id: newUser.user.id } };
  }

  private validateEmail(email: string): boolean {
    const re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@(([^<>()[\]\\.,;:\s@"]+\.)+[^<>()[\]\\.,;:\s@"]{2,})$/i;
    return re.test(String(email).toLowerCase());
  }

  // ... other methods
}
