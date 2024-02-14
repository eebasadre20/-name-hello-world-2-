import { sign } from 'jsonwebtoken';
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
  // Assuming the existence of a function to fetch the manager's details using managerId
  const manager = fetchManagerDetails(managerId); // This function needs to be implemented to fetch manager details

  const accessTokenExpiresIn = 24 * 60 * 60; // 24 hours in seconds
  const refreshTokenExpiresIn = rememberInHours * 60 * 60; // Convert hours to seconds based on remember_in_hours

  const access_token = sign(
    { 
      id: manager.id, 
      email: manager.email, // Include email in the payload for more detailed claims
    },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: accessTokenExpiresIn }
  );

  const refresh_token = sign(
    { 
      id: manager.id, 
      email: manager.email, // Include email in the payload for more detailed claims
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

function fetchManagerDetails(managerId: string): Manager {
  // Implementation to fetch manager details from the database or any data source
  // This should be replaced with actual data fetching logic.
  // For the purpose of this example, returning a mock object
  return {
    id: managerId,
    email: 'manager@example.com',
    // other manager properties
  } as Manager;
}
