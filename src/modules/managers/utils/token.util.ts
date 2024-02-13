import { sign } from 'jsonwebtoken';
import { Manager } from '../../entities/managers';

export const generateAccessToken = (user: Manager): string => {
  const expiresIn = 24 * 60 * 60; // 24 hours in seconds
  return sign(
    {
      id: user.id,
      email: user.email,
    },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn }
  );
};

export const generateRefreshToken = (user: Manager, rememberInHours: number): string => {
  const expiresIn = rememberInHours * 60 * 60; // Convert hours to seconds
  return sign(
    {
      id: user.id,
      email: user.email,
    },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn }
  );
};

// Existing function to generate both access and refresh tokens remains unchanged
export const generateTokens = (userId: string) => {
  const accessTokenExpiresIn = 24 * 60 * 60; // 24 hours in seconds
  const refreshTokenExpiresIn = 30 * 24 * 60 * 60; // 30 days in seconds

  const access_token = sign(
    { id: userId },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: accessTokenExpiresIn }
  );

  const refresh_token = sign(
    { id: userId },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: refreshTokenExpiresIn }
  );

  return {
    access_token,
    refresh_token,
    expires_in: accessTokenExpiresIn,
    refresh_token_expires_in: refreshTokenExpiresIn,
  };
};
