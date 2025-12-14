// middleware.ts ← put this in your project root (same level as package.json)
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

export function middleware(request: NextRequest) {
  const url = request.nextUrl;
  const cookies = request.cookies.getAll();
  const hasSession = cookies.some(c => c.name.includes("session") || c.name.includes("token"));

  // If logged in → don't let them see login page
  if (hasSession && url.pathname === "/login") {
    return NextResponse.redirect(new URL("/dashboard", request.url));
  }

  // not logged in → protect dashboard
  if (!hasSession && url.pathname.startsWith("/dashboard")) {
    return NextResponse.redirect(new URL("/login", request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/dashboard/:path*", "/login"],
};