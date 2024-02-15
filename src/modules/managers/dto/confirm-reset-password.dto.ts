 { IsNotEmpty, IsString, MinLength, Matches } from 'class-validator';
import { IsPassword } from 'src/shared/validators/is-password.validator';
import configs from '@configs/index';

const configService = new ConfigService(configs());

export class ConfirmResetPasswordRequest {
  @IsString()
  @IsNotEmpty({ message: 'reset_token is required' })
  reset_token: string;

  @IsString()
  @IsNotEmpty({ message: 'password is required' })
  @MinLength(configService.get('authentication.passwordMinLength'), { message: 'Password is invalid' })
  @IsPassword({ message: 'Password is invalid' })
  password: string;

  @IsString()
  @IsNotEmpty({ message: 'password_confirmation is required' })
  password_confirmation: string;

  @Matches(value => value.password, { message: 'Password confirmation does not match' })
  passwordConfirmationMatch(): boolean {
    return this.password === this.password_confirmation;
  }
}

export class ConfirmResetPasswordResponse {
  message?: string; // Made optional to match the requirement

  constructor(message?: string) {
    this.message = message;
  }
}
