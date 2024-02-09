import {
  Body,
  Controller,
  Post,
  HttpCode,
  HttpStatus,
  BadRequestException,
  UnauthorizedException,
  InternalServerErrorException,
  HttpException,
} from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { AuthenticateUserDto, AuthenticateUserRequest, AuthenticationResponse } from './dto/authenticate-user.dto';
import { ResetPasswordRequest, ResetPasswordResponse } from './dtos/reset-password.dto';
import { SuccessResponseDto } from './dtos/success-response.dto';

@ApiTags('Auth')
@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/api/auth/login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() authenticateUserDto: AuthenticateUserDto): Promise<SuccessResponseDto | AuthenticationResponse> {
    try {
      const { email, password, remember_me } = authenticateUserDto;

      if (!email || !password) {
        throw new BadRequestException('Email and password fields cannot be empty.');
      }

      const response = await this.authService.authenticateUser({
        email,
        password,
        rememberMe: remember_me,
      });

      return {
        status: HttpStatus.OK,
        message: 'User authenticated successfully.',
        access_token: response.sessionToken,
        user: {
          id: response.user.id,
          email: response.user.email,
        },
      };
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw new BadRequestException(error.response || 'Invalid email format or email cannot be empty.');
      } else if (error.status === HttpStatus.UNAUTHORIZED) {
        throw new UnauthorizedException('The email or password is incorrect.');
      } else {
        throw new InternalServerErrorException('An unexpected error occurred on the server.');
      }
    }
  }

  @Post('/api/password/forgot')
  @HttpCode(HttpStatus.OK)
  async issuePasswordResetToken(@Body() body: { email: string }): Promise<{ message: string }> {
    if (!body || !body.email) {
      throw new BadRequestException('Email is required.');
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(body.email)) {
      throw new BadRequestException('Invalid email format.');
    }

    // Call the business logic to issue a password reset token
    // Assuming there is a method in the AuthService to handle this
    try {
      await this.authService.issuePasswordResetToken(body.email);
      return { message: 'Password reset token issued successfully. Please check your email.' };
    } catch (error) {
      if (error.status === HttpStatus.NOT_FOUND) {
        throw error;
      }
      // Handle other possible exceptions that could be thrown by the business logic
      throw new BadRequestException(error.message);
    }
  }

  @Post('/api/password/reset')
  async resetPassword(@Body() body: ResetPasswordRequest): Promise<ResetPasswordResponse> {
    if (!body.token) {
      throw new HttpException('Token is required.', HttpStatus.BAD_REQUEST);
    }
    if (!body.password) {
      throw new HttpException('Password is required.', HttpStatus.BAD_REQUEST);
    }
    if (body.password.length < 8) {
      throw new HttpException('Password must be at least 8 characters long.', HttpStatus.BAD_REQUEST);
    }

    try {
      const response = await this.authService.resetPassword(body);
      return response;
    } catch (error) {
      if (error.status === HttpStatus.BAD_REQUEST) {
        throw new HttpException(error.response, HttpStatus.BAD_REQUEST);
      } else if (error.status === HttpStatus.UNAUTHORIZED) {
        throw new HttpException(error.response, HttpStatus.UNAUTHORIZED);
      } else {
        throw new HttpException('An unexpected error occurred on the server.', HttpStatus.INTERNAL_SERVER_ERROR);
      }
    }
  }

  // ... other methods ...
}
