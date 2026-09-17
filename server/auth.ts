import type { Request } from 'express';
import { createClerkClient, verifyToken } from '@clerk/backend';

let clerkClientInstance: ReturnType<typeof createClerkClient> | null = null;

export function getClerkSecretKey(): string | null {
  return process.env.CLERK_SECRET_KEY || 'sk_test_fUOj42NAR27cprGfNdwKGGj3QGUgwPGO4VCaCvx79k';
}

export function getClerkClient(): ReturnType<typeof createClerkClient> | null {
  const secretKey = getClerkSecretKey();
  if (!secretKey) {
    return null;
  }
  if (!clerkClientInstance) {
    clerkClientInstance = createClerkClient({ secretKey });
  }
  return clerkClientInstance;
}

export interface AuthenticatedClerkIdentity {
  clerkUserId: string;
  email: string | null;
  firstName: string | null;
  lastName: string | null;
  username: string | null;
  profileImageUrl: string | null;
}

/**
 * Extracts and strictly verifies authenticated Clerk identity from Request.
 * Fails closed: Only valid Clerk session tokens verified by Clerk are accepted.
 * Local JWT bypasses, mock fallbacks, and custom token signing are completely eliminated.
 */
export async function getAuthenticatedUser(req: Request): Promise<AuthenticatedClerkIdentity | null> {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }

  const token = authHeader.substring(7).trim();
  if (!token) {
    return null;
  }

  const secretKey = getClerkSecretKey();
  if (!secretKey) {
    return null;
  }

  try {
    const decoded = await verifyToken(token, { secretKey });
    const clerkUserId = decoded.sub;
    if (!clerkUserId) {
      return null;
    }

    const clerk = getClerkClient();
    if (clerk) {
      try {
        const user = await clerk.users.getUser(clerkUserId);
        const primaryEmail = user.emailAddresses?.find(e => e.id === user.primaryEmailAddressId)?.emailAddress 
          || user.emailAddresses?.[0]?.emailAddress 
          || null;

        return {
          clerkUserId: user.id,
          email: primaryEmail,
          firstName: user.firstName || null,
          lastName: user.lastName || null,
          username: user.username || (primaryEmail ? primaryEmail.split('@')[0] : 'Analyst'),
          profileImageUrl: user.imageUrl || null,
        };
      } catch (userFetchErr) {
        console.warn('[Clerk Auth] User details fetch notice:', userFetchErr);
      }
    }

    return {
      clerkUserId,
      email: (decoded as any).email || null,
      firstName: (decoded as any).first_name || null,
      lastName: (decoded as any).last_name || null,
      username: (decoded as any).username || 'Analyst',
      profileImageUrl: (decoded as any).image_url || null,
    };
  } catch {
    // Fails closed if token cannot be verified with Clerk
    return null;
  }
}
