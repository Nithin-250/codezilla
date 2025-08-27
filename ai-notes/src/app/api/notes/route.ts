import { NextResponse } from 'next/server';
import { connectToDatabase } from '@/lib/db';
import { getUserIdFromRequest } from '@/lib/auth';
import { NoteModel } from '@/models/Note';

export async function GET() {
  const userId = getUserIdFromRequest();
  if (!userId) return NextResponse.json([], { status: 200 });
  await connectToDatabase();
  const notes = await NoteModel.find({ userId }).sort({ createdAt: -1 }).lean();
  return NextResponse.json(notes);
}

export async function POST(request: Request) {
  const userId = getUserIdFromRequest();
  if (!userId) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  const { title = '', content = '' } = await request.json();
  await connectToDatabase();
  const tags = extractTags(content);
  const note = await NoteModel.create({ userId, title, content, tags });
  return NextResponse.json(note);
}

function extractTags(text: string): string[] {
  const words = (text || '').toLowerCase().match(/[a-zA-Z]{4,}/g) || [];
  const frequency = new Map<string, number>();
  for (const w of words) frequency.set(w, (frequency.get(w) || 0) + 1);
  return Array.from(frequency.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([w]) => w);
}

