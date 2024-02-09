import { Body, Controller, Post } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { UsersService } from './users.service';
import { VerifyEmailRequestDto } from './dto/verify-email-request.dto';
import { VerifyEmailResponseDto } from './dto/verify-email-response.dto';

@Controller('admin/users')
@ApiTags('Admin/Users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post('email-confirmation')
  async confirmEmail(@Body() verifyEmailDto: VerifyEmailRequestDto): Promise<VerifyEmailResponseDto> {
    return this.usersService.verifyEmail(verifyEmailDto);
  }

  // ... other controller methods ...
}
