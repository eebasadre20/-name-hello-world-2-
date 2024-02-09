import {
  IsBoolean,
  IsEmail,
  IsNotEmpty,
  IsString,
  Matches,
  MinLength,
  ValidateIf,
} from 'class-validator';

export class RegisterUserDto {
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @IsString()
  @MinLength(8)
  @Matches(/((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {
    message: 'Password too weak',
  })
  password: string;

  @IsString()
  @IsNotEmpty()
  full_name: string;

  @IsBoolean()
  @ValidateIf(o => o.terms_of_service_accepted === true, {
    message: 'Terms of service must be accepted',
  })
  terms_of_service_accepted: boolean;

  @IsBoolean()
  @ValidateIf(o => o.privacy_policy_accepted === true, {
    message: 'Privacy policy must be accepted',
  })
  privacy_policy_accepted: boolean;

  // The following properties are from the new code and should be included
  @IsString()
  @IsNotEmpty()
  username: string;

  @IsString()
  @IsNotEmpty()
  @ValidateIf(o => o.referral_code != null)
  referral_code?: string;
}
