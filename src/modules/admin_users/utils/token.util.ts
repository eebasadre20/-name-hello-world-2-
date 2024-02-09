import { sign, verify } from 'jsonwebtoken';
import { AdminUser } from '../../entities/admin_users';

interface TokenPayload {
  id: number;
  email: string;
}

export const generateToken = (user: AdminUser, secret: string, expiresIn: string | number): string => {
  const payload: TokenPayload = {
    id: user.id,
    email: user.email,
  };
  return sign(payload, secret, { expiresIn });
};

export const verifyToken = (token: string, secret: string): TokenPayload | null => {
  try {
    return verify(token, secret) as TokenPayload;
  } catch (error) {
    return null;
  }
};
