import { NextResponse } from "next/server";

export async function GET() {
  return NextResponse.redirect("https://growth-easy-analytics-2.onrender.com/api/auth/ga4/start");
}