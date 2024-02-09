import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from 'src/entities/users';
import { AuthenticateUserRequest, AuthenticationResponse } from './dto/authenticate-user.dto';
import { validateEmailFormat } from '../users/utils/validation.util';
import { comparePasswords } from '../users/utils/password.util';
import { UsersService } from '../users/users.service';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private usersService: UsersService,
  ) {}

  async authenticateUser(authenticateUserRequest: AuthenticateUserRequest): Promise<AuthenticationResponse> {
    const { email, password, rememberMe } = authenticateUserRequest;

    if (!email || !password) {
      throw new BadRequestException('Email and password fields cannot be empty.');
    }

    if (!validateEmailFormat(email)) {
      throw new BadRequestException('Invalid email format.');
    }

    const user = await this.usersService.findUserByEmail(email);
    if (!user) {
      throw new BadRequestException('Invalid login credentials.');
    }

    const isPasswordValid = comparePasswords(password, user.password_hash);
    if (!isPasswordValid) {
      throw new BadRequestException('Invalid login credentials.');
    }

    const token = this.usersService.generateSessionToken(user.id);

    if (rememberMe) {
      const rememberMeToken = this.usersService.generateSessionToken(user.id); // Assuming this generates a suitable token
      this.usersService.storeRememberMeToken(user.id, rememberMeToken);
    }

    const authenticationResponse: AuthenticationResponse = {
      token: token,
      user: {
        id: user.id,
        email: user.email,
        fullName: user.full_name,
        // ... include other necessary user profile fields
      },
    };

    return authenticationResponse;
  }

  // ... other methods ...
}
