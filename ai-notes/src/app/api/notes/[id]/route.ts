import { NextResponse } from 'next/server';
import { connectToDatabase } from '@/lib/db';
import { getUserIdFromRequest } from '@/lib/auth';
import { NoteModel } from '@/models/Note';

export async function DELETE(
  _req: Request,
  { params }: { params: { id: string } }
) {
  const userId = getUserIdFromRequest();
  if (!userId) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  await connectToDatabase();
  await NoteModel.deleteOne({ _id: params.id, userId });
  return NextResponse.json({ ok: true });
}

export async function PUT(
  req: Request,
  { params }: { params: { id: string } }
) {
  const userId = getUserIdFromRequest();
  if (!userId) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  const body = await req.json();
  await connectToDatabase();
  const updated = await NoteModel.findOneAndUpdate(
    { _id: params.id, userId },
    { $set: body },
    { new: true }
  );
  return NextResponse.json(updated);
}

