import { NextResponse } from 'next/server';
import { connectToDatabase } from '@/lib/db';
import { UserModel } from '@/models/User';
import bcrypt from 'bcryptjs';
import { signAuthToken } from '@/lib/auth';

export async function POST(request: Request) {
  try {
    const { email, password } = await request.json();
    if (!email || !password) {
      return NextResponse.json({ error: 'Missing fields' }, { status: 400 });
    }
    await connectToDatabase();
    const user = await UserModel.findOne({ email });
    if (!user) return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 });
    const token = signAuthToken(user._id.toString());
    const res = NextResponse.json({ ok: true });
    res.cookies.set('token', token, { httpOnly: true, sameSite: 'lax', path: '/' });
    return res;
  } catch (e) {
    return NextResponse.json({ error: 'Server error' }, { status: 500 });
  }
}

