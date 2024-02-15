
import { sign } from 'jsonwebtoken';
import { randomBytes } from 'crypto';
import { differenceInHours } from 'date-fns';
import { Manager } from '../../entities/managers';

export const generateAccessToken = (user: Manager): string => {
  const expiresIn = 24 * 60 * 60; // 24 hours in seconds
  return sign(
    {
      id: user.id,
      email: user.email,
      // Additional claims can be added here if necessary
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
      // Additional claims can be added here if necessary
    },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn }
  );
};

export const generateTokens = (managerId: string, rememberInHours: number) => {
  const manager = fetchManagerDetails(managerId);

  const accessTokenExpiresIn = 24 * 60 * 60; // 24 hours in seconds
  const refreshTokenExpiresIn = rememberInHours * 60 * 60; // Convert hours to seconds based on remember_in_hours

  const access_token = sign(
    { 
      id: manager.id, 
      email: manager.email,
    },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: accessTokenExpiresIn }
  );

  const refresh_token = sign(
    { 
      id: manager.id, 
      email: manager.email,
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

export const validateTokenExpiration = (sentAt: Date, expiresInHours: number): boolean => {
  const currentDateTime = new Date();
  const hoursDifference = differenceInHours(currentDateTime, sentAt);
  return hoursDifference < expiresInHours;
};

export const confirmManagerEmail = async (token: string): Promise<Manager> => {
  const manager = await fetchManagerByConfirmationToken(token);
  if (!manager) {
    throw new Error('Confirmation token is not valid');
  }

  if (!validateTokenExpiration(manager.confirmation_sent_at, email_expired_in)) {
    throw new Error('Confirmation token is expired');
  }

  manager.confirmed_at = new Date();
  return manager;
};

function fetchManagerDetails(managerId: string): Manager {
  return {
    id: managerId,
    email: 'manager@example.com',
    // other manager properties
  } as Manager;
}

export const generateConfirmationToken = async (): Promise<string> => {
  return new Promise((resolve, reject) => {
    randomBytes(32, (err, buffer) => {
      if (err) {
        reject(err);
      } else {
        resolve(buffer.toString('hex'));
      }
    });
  });
};
