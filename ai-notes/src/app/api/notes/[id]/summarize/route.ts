import { NextResponse } from 'next/server';
import { connectToDatabase } from '@/lib/db';
import { getUserIdFromRequest } from '@/lib/auth';
import { NoteModel } from '@/models/Note';
import OpenAI from 'openai';

export async function POST(
  _req: Request,
  { params }: { params: { id: string } }
) {
  const userId = getUserIdFromRequest();
  if (!userId) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  await connectToDatabase();
  const note = await NoteModel.findOne({ _id: params.id, userId });
  if (!note) return NextResponse.json({ error: 'Not found' }, { status: 404 });

  try {
    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey) throw new Error('Missing OPENAI_API_KEY');
    const client = new OpenAI({ apiKey });
    const prompt = `Summarize the following note in 5 concise bullet points. Keep key facts and terms.\n\n${note.content}`;
    const completion = await client.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [
        { role: 'system', content: 'You are a helpful academic note summarizer.' },
        { role: 'user', content: prompt },
      ],
      temperature: 0.3,
    });
    const summary = completion.choices[0]?.message?.content?.trim() || '';
    if (summary) {
      note.content = `${note.content}\n\n---\nSummary:\n${summary}`;
      note.tags = Array.from(new Set([...(note.tags || []), ...extractTags(summary)]));
      await note.save();
    }
    return NextResponse.json({ ok: true });
  } catch (e) {
    // Fallback: naive summary
    const naive = naiveSummarize(note.content);
    note.content = `${note.content}\n\n---\nSummary:\n${naive}`;
    note.tags = Array.from(new Set([...(note.tags || []), ...extractTags(naive)]));
    await note.save();
    return NextResponse.json({ ok: true, fallback: true });
  }
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

function naiveSummarize(text: string): string {
  const lines = (text || '').split(/\n+/).filter(Boolean);
  const first = lines.slice(0, 5);
  return first.map(l => `- ${l.slice(0, 180)}`).join('\n');
}

