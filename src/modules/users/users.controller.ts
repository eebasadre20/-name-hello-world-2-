import {
  Body,
  Controller,
  Post,
  HttpCode,
  HttpStatus,
  BadRequestException,
  ConflictException,
  HttpException,
  InternalServerErrorException,
} from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { UsersService } from './users.service';
import {
  RegisterUserRequest,
  RegistrationResponse,
  RegisterUserResponse,
  VerifyEmailRequest,
  VerifyEmailResponse,
  ResetPasswordRequest,
  ResetPasswordResponse,
  IssuePasswordResetTokenRequest,
  MessageResponse,
  RequestPasswordResetDTO,
  PasswordResetRequestResponse,
  ConfirmPasswordResetRequest,
  ConfirmPasswordResetResponse,
  VerifyEmailRequestDto,
  MessageResponseDto,
} from './dto';

@ApiTags('Users')
@Controller('api/users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  // ... other existing controller methods ...

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() registerUserDto: RegisterUserRequest): Promise<RegistrationResponse | RegisterUserResponse> {
    try {
      return await this.usersService.registerNewUser(registerUserDto);
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw new BadRequestException(error.response);
      } else if (error instanceof ConflictException) {
        throw new ConflictException(error.response);
      } else {
        throw error;
      }
    }
  }

  // Merged the new verifyEmail method with the existing one
  @Post('verify-email')
  @HttpCode(HttpStatus.OK)
  async verifyEmail(@Body() verifyEmailDto: VerifyEmailRequest | VerifyEmailRequestDto): Promise<VerifyEmailResponse | MessageResponse | MessageResponseDto> {
    if (verifyEmailDto instanceof VerifyEmailRequestDto) {
      return await this.usersService.verifyEmail(verifyEmailDto);
    } else {
      // ... existing verifyEmail method code ...
    }
  }

  // ... other existing controller methods ...

  @Post('password-reset/request')
  @HttpCode(HttpStatus.OK)
  async requestPasswordReset(@Body() requestPasswordResetDto: RequestPasswordResetDTO): Promise<PasswordResetRequestResponse | MessageResponse> {
    // ... existing requestPasswordReset method code ...
  }

  @Post('password-reset/confirm')
  async resetPassword(@Body() resetPasswordDto: ResetPasswordRequest): Promise<ResetPasswordResponse> {
    // ... existing resetPassword method code ...
  }

  @Post('confirm-password-reset')
  async confirmPasswordReset(@Body() confirmPasswordResetDto: ConfirmPasswordResetRequest): Promise<ConfirmPasswordResetResponse> {
    // ... existing confirmPasswordReset method code ...
  }

  // New method added from new code
  @Post('password-reset')
  async issuePasswordResetToken(@Body() requestPasswordResetDto: RequestPasswordResetDTO): Promise<MessageResponseDto> {
    try {
      // Validate email format
      if (!requestPasswordResetDto.email || !/^\S+@\S+\.\S+$/.test(requestPasswordResetDto.email)) {
        throw new BadRequestException('Invalid email format.');
      }

      return await this.usersService.issuePasswordResetToken(requestPasswordResetDto);
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw new BadRequestException('The request was malformed or had invalid parameters.');
      } else if (error instanceof HttpException) {
        throw error;
      } else {
        throw new InternalServerErrorException('An unexpected error occurred on the server.');
      }
    }
  }

  // ... other existing controller methods ...
}
