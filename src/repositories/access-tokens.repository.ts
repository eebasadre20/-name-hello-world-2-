
import { Injectable } from '@nestjs/common'
import { BaseRepository } from 'src/shared/base.repository'
import { ConfigService } from '@nestjs/config'
import { AccessToken } from '@entities/access_tokens'
import { DeleteResult } from 'typeorm'

@Injectable()
export class AccessTokenRepository extends BaseRepository<AccessToken> {
  constructor(private configService: ConfigService) {
    super();
  }

  async deleteByRefreshToken(refreshToken: string): Promise<DeleteResult> {
    return this.delete({ refresh_token: refreshToken });
  }
}
