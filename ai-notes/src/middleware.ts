import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const token = request.cookies.get('token');
  const isAuthed = Boolean(token?.value);
  const isAuthPage = request.nextUrl.pathname.startsWith('/login') || request.nextUrl.pathname.startsWith('/register');

  if (!isAuthed && request.nextUrl.pathname.startsWith('/dashboard')) {
    const url = new URL('/login', request.url);
    return NextResponse.redirect(url);
  }
  if (isAuthed && isAuthPage) {
    const url = new URL('/dashboard', request.url);
    return NextResponse.redirect(url);
  }
  return NextResponse.next();
}

export const config = {
  matcher: ['/dashboard', '/login', '/register'],
};

