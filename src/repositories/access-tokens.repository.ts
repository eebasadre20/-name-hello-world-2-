
import { Injectable, BadRequestException } from '@nestjs/common'
import { BaseRepository } from 'src/shared/base.repository'
import { ConfigService } from '@nestjs/config'
import { AccessToken } from 'src/entities/access_tokens'
import { DeleteResult } from 'typeorm'
import { JwtService } from '@nestjs/jwt'

@Injectable()
export class AccessTokenRepository extends BaseRepository<AccessToken> {
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService
  ) {
    super();
  }

  async deleteByRefreshToken(refreshToken: string): Promise<DeleteResult> {
    return this.delete({ refresh_token: refreshToken });
  }

  async refreshManagerToken(refreshToken: string, scope: string): Promise<any> {
    const rememberInHours = this.configService.get('auth.rememberMeDurationInHours');
    const tokenValid = this.jwtService.verify(refreshToken, {
      secret: this.configService.get('jwt.refreshSecret'),
    });

    if (!tokenValid) {
      throw new BadRequestException('Refresh token is not valid');
    }

    await this.deleteByRefreshToken(refreshToken);

    const newAccessToken = this.jwtService.sign({ scope }, { expiresIn: '24h' });
    const newRefreshToken = this.jwtService.sign({ scope }, { expiresIn: `${rememberInHours}h` });

    // Assuming the manager's id and table name are retrieved from the token
    const managerId = tokenValid.sub; // Substitute with actual logic to extract manager ID
    const tableName = scope;

    return {
      access_token: newAccessToken,
      refresh_token: newRefreshToken,
      resource_owner: tableName,
      resource_id: managerId,
      expires_in: 24 * 60 * 60, // 24 hours in seconds
      token_type: 'Bearer',
      scope: tableName,
      created_at: new Date(),
      refresh_token_expires_in: rememberInHours * 60 * 60, // Convert hours to seconds
    };
  }
}
