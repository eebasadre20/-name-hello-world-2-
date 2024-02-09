import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AdminUser } from 'src/entities/admin_users';
import { RegisterAdminUserRequest, RegisterAdminUserResponse, ConfirmResetPasswordRequest, SuccessResponse } from './dto';
import { RefreshTokenRequest, RefreshTokenResponse } from './dto/refresh-token.dto';
import { LoginRequest, LoginResponse } from './dto/login.dto';
import * as bcrypt from 'bcrypt';
import { sendConfirmationEmail } from './utils/email.util';
import { v4 as uuidv4 } from 'uuid';
import { JwtService } from '@nestjs/jwt'; // Assuming JWT is used for token management
import { generateToken } from './utils/token.util'; // Assuming custom token utility is used alongside JWT for specific cases

@Injectable()
export class AdminUsersService {
  constructor(
    @InjectRepository(AdminUser)
    private adminUsersRepository: Repository<AdminUser>,
    private jwtService: JwtService, // Inject JwtService, added from new code
  ) {}

  async signupWithEmail({ email, password }: RegisterAdminUserRequest): Promise<RegisterAdminUserResponse> {
    const existingUser = await this.adminUsersRepository.findOne({ where: { email } });
    if (existingUser) {
      throw new BadRequestException('Email is already taken');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const confirmationToken = uuidv4();

    const newUser = this.adminUsersRepository.create({
      email,
      password: hashedPassword,
      confirmation_token: confirmationToken,
      confirmed_at: null,
    });

    await this.adminUsersRepository.save(newUser);

    const confirmationUrl = `http://frontend.url/confirm?confirmation_token=${confirmationToken}`;
    await sendConfirmationEmail(email, confirmationToken, confirmationUrl);

    return { user: newUser };
  }

  async confirmResetPassword({ token, password }: ConfirmResetPasswordRequest): Promise<SuccessResponse> {
    const user = await this.adminUsersRepository.findOne({ where: { reset_password_token: token } });
    if (!user) {
      throw new BadRequestException('Token is not valid');
    }

    const resetPasswordExpireInHours = 2; // Assuming 2 hours for password reset token expiration
    const expirationDate = new Date(user.reset_password_sent_at);
    expirationDate.setHours(expirationDate.getHours() + resetPasswordExpireInHours);

    if (new Date() > expirationDate) {
      throw new BadRequestException('Token is expired');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    user.password = hashedPassword;
    user.reset_password_token = null;
    user.reset_password_sent_at = null;

    await this.adminUsersRepository.save(user);

    return { message: "Password reset successfully" };
  }

  async refreshToken({ refresh_token, scope }: RefreshTokenRequest): Promise<RefreshTokenResponse> {
    // Validate the refresh token
    let payload: any;
    try {
      payload = this.jwtService.verify(refresh_token);
    } catch (e) {
      throw new BadRequestException('Refresh token is not valid');
    }

    // Assuming payload contains userId and scope
    if (!payload || payload.scope !== scope) {
      throw new BadRequestException('Refresh token is not valid');
    }

    const user = await this.adminUsersRepository.findOne({ where: { id: payload.userId } });
    if (!user) {
      throw new BadRequestException('User not found');
    }

    // Delete old refresh token logic here (Assuming it's managed externally or via a blacklist)

    // Generate new tokens
    const newAccessToken = this.jwtService.sign({ userId: user.id, scope }, { expiresIn: '24h' });
    const newRefreshToken = this.jwtService.sign({ userId: user.id, scope }, { expiresIn: `${payload.remember_in_hours}h` });

    // Construct response
    const response: RefreshTokenResponse = {
      access_token: newAccessToken,
      refresh_token: newRefreshToken,
      resource_owner: scope, // Assuming scope is the table name
      resource_id: user.id.toString(),
      expires_in: 86400, // 24 hours in seconds
      token_type: 'Bearer',
      scope,
      created_at: new Date().toISOString(),
      refresh_token_expires_in: payload.remember_in_hours * 3600, // Convert hours to seconds
    };

    return response;
  }

  async emailLogin({ email, password }: LoginRequest): Promise<LoginResponse> {
    const user = await this.adminUsersRepository.findOne({ where: { email } });
    if (!user) {
      throw new BadRequestException('Email or password is not valid');
    }

    const isPasswordMatching = await bcrypt.compare(password, user.password);
    if (!isPasswordMatching) {
      throw new BadRequestException('Email or password is not valid');
    }

    if (!user.confirmed_at) {
      throw new BadRequestException('User is not confirmed');
    }

    const accessToken = generateToken({ userId: user.id }, '24h');
    const refreshToken = generateToken({ userId: user.id }, '48h'); // Assuming remember_in_hours is 48

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      resource_owner: 'admin_users',
      resource_id: user.id.toString(),
      expires_in: 86400, // 24 hours in seconds
      token_type: 'Bearer',
      scope: 'admin_users',
      created_at: new Date().toISOString(),
      refresh_token_expires_in: 172800, // 48 hours in seconds
    };
  }

  // No other methods to merge, all required functionalities are included.
}
