import {
  Body,
  Param,
  Controller,
  Put as MethodPut,
  HttpCode,
  HttpStatus,
  UseGuards,
  BadRequestException,
  Post,
  HttpException,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { AuthGuard } from 'src/guards/auth.guard';
import { UserService } from './user.service';
import { UpdateUserProfileRequest, UpdateUserProfileResponse } from './dto/update-user-profile.dto';
import { ResendVerificationEmailRequest } from './dto/resend-verification-email.dto';

@ApiTags('User')
@Controller('/api/users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @MethodPut('/:id/profile')
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  async updateProfile(
    @Param('id') id: number,
    @Body() request: UpdateUserProfileRequest,
  ): Promise<UpdateUserProfileResponse> {
    if (!id) {
      throw new BadRequestException('User not found.');
    }

    if (request.email && !validateEmailFormat(request.email)) {
      throw new BadRequestException('Invalid email format.');
    }

    if (request.full_name && request.full_name.trim() === '') {
      throw new BadRequestException('Full name cannot be empty.');
    }

    const updatedUser = await this.userService.updateUserProfile({ id, ...request });
    return {
      status: HttpStatus.OK,
      message: 'User profile updated successfully.',
      user: updatedUser,
    };
  }

  @Post('/resend-verification-email')
  @UsePipes(new ValidationPipe({ transform: true }))
  async resendVerificationEmail(@Body() request: ResendVerificationEmailRequest) {
    try {
      const response = await this.userService.resendVerificationEmail(request);
      return response;
    } catch (error) {
      if (error.message === 'User with the given email does not exist.') {
        throw new HttpException('Invalid email or email not registered.', HttpStatus.NOT_FOUND);
      }
      // Handle other possible errors from the business logic or unexpected errors
      throw new HttpException('Internal Server Error', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  // ... other controller methods ...
}

function validateEmailFormat(email: string): boolean {
  // This is a simple regex for demonstration purposes.
  // You should use a more robust regex for a production application.
  const emailRegex = /^\S+@\S+\.\S+$/;
  return emailRegex.test(email);
}
