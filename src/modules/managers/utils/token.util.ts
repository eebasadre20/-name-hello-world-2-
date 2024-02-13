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
