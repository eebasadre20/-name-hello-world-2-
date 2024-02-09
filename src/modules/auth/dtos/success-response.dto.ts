export class UserProfile {
  id: number;
  email: string;
  full_name: string;
  terms_of_service_accepted: boolean;
  privacy_policy_accepted: boolean;
  email_verified: boolean;
  // Add any other user profile information that should be returned on success
  // Exclude sensitive data like passwords
}

export class SuccessResponseDto {
  token: string;
  user: UserProfile;
}
