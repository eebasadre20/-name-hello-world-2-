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

export const generateTokens = (managerId: string, rememberInHours: number) => {
  // Assuming the existence of a function to fetch the manager's details using managerId
  // This is a placeholder function. Replace it with the actual function to fetch manager details.
  const manager = fetchManagerDetails(managerId); // Placeholder function

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

// Placeholder function for fetching manager details. Replace with actual implementation.
function fetchManagerDetails(managerId: string): Manager {
  // Implementation to fetch manager details from the database or any data source
  // This is just a placeholder. Replace it with actual data fetching logic.
  return {
    id: managerId,
    email: 'manager@example.com',
    // other manager properties
  } as Manager;
}
