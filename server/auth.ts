import type { Request } from 'express';
import { createClerkClient, verifyToken } from '@clerk/backend';
import crypto from 'crypto';

let clerkClientInstance: ReturnType<typeof createClerkClient> | null = null;
const JWT_SECRET = process.env.JWT_SECRET || 'cybersec_jwt_secret_key_2026_prod_secure_92183';

function base64UrlDecode(str: string): string {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64').toString('utf-8');
}

function verifyLocalJWT(token: string, secret: string): any {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [encodedHeader, encodedPayload, signature] = parts;
    const expectedSignature = crypto
      .createHmac('sha256', secret)
      .update(`${encodedHeader}.${encodedPayload}`)
      .digest('base64')
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');

    if (signature !== expectedSignature) return null;
    const payload = JSON.parse(base64UrlDecode(encodedPayload));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

export function getClerkClient(): ReturnType<typeof createClerkClient> | null {
  const secretKey = process.env.CLERK_SECRET_KEY;
  if (!secretKey || secretKey.includes('sk_test_LfO6rsSqkZ0NjdBXIYuqBBgZzKXHSEEMlq319qvsqe')) {
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
 * Extracts and strictly verifies authenticated identity from Request.
 * Supports both verified Clerk session tokens and verified local JWT tokens.
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

  const secretKey = process.env.CLERK_SECRET_KEY;
  const isDeadClerkPlaceholder = !secretKey || secretKey.includes('sk_test_LfO6rsSqkZ0NjdBXIYuqBBgZzKXHSEEMlq319qvsqe');

  // 1. Try Clerk Token Verification if live key is present
  if (!isDeadClerkPlaceholder) {
    try {
      const decoded = await verifyToken(token, { secretKey });
      const clerkUserId = decoded.sub;
      if (clerkUserId) {
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
            console.warn('[Clerk Auth] Failed to fetch full user details, using token claims:', userFetchErr);
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
      }
    } catch {
      // Fall through to check if it's a local JWT token
    }
  }

  // 2. Try Local JWT Verification
  const localPayload = verifyLocalJWT(token, JWT_SECRET);
  if (localPayload && (localPayload.userId || localPayload.username)) {
    const username = localPayload.username || 'admin';
    const email = localPayload.email || (username === 'admin' ? 'admin@phishguard.security' : `${username}@cybersec.org`);
    const isAdmin = 
      username === 'admin' || 
      localPayload.role === 'Admin';

    return {
      clerkUserId: `local_${localPayload.userId || username}`,
      email,
      firstName: localPayload.firstName || (isAdmin ? 'Administrator' : username),
      lastName: localPayload.lastName || 'Analyst',
      username,
      profileImageUrl: localPayload.profileImage || (isAdmin ? 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&q=80&w=250' : null),
    };
  }

  return null;
}
