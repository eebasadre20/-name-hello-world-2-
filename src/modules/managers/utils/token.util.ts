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

export const generateTokens = (user: Manager, rememberInHours: number) => {
  const accessTokenExpiresIn = 24 * 60 * 60; // 24 hours in seconds
  const refreshTokenExpiresIn = rememberInHours * 60 * 60; // Convert hours to seconds based on remember_in_hours

  const access_token = sign(
    { 
      id: user.id, 
      email: user.email, // Include email in the payload for more detailed claims
    },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: accessTokenExpiresIn }
  );

  const refresh_token = sign(
    { 
      id: user.id, 
      email: user.email, // Include email in the payload for more detailed claims
    },
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
