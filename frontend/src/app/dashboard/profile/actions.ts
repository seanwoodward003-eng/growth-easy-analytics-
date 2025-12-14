// src/app/dashboard/profile/actions.ts
"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error("Missing JWT_SECRET in environment variables");
}

export type Session = {
  user: {
    id: number;
    email: string;
    shopifyConnected?: boolean;
    ga4Connected?: boolean;
    hubspotConnected?: boolean;
  };
  expires: string;
} | null;

export async function getServerSession(): Promise<Session> {
  const cookieStore = await cookies();
  const token = cookieStore.get("access_token")?.value;

  if (!token) {
    redirect("/");
  }

  try {
    const verified = jwt.verify(token, JWT_SECRET!);

    if (typeof verified === "string" || !verified || typeof verified !== "object") {
      redirect("/");
    }

    const payload = verified as {
      sub: string;
      email: string;
      exp: number;
      shopifyConnected?: boolean;
      ga4Connected?: boolean;
      hubspotConnected?: boolean;
    };

    if (!payload.sub || !payload.email || typeof payload.exp !== "number") {
      redirect("/");
    }

    return {
      user: {
        id: Number(payload.sub),
        email: payload.email,
        shopifyConnected: payload.shopifyConnected,
        ga4Connected: payload.ga4Connected,
        hubspotConnected: payload.hubspotConnected,
      },
      expires: new Date(payload.exp * 1000).toISOString(),
    };
  } catch {
    redirect("/");
  }
}