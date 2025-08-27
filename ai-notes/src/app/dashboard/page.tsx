'use client';
import { useEffect, useState } from 'react';

type Note = {
  _id: string;
  title: string;
  content: string;
  tags: string[];
  createdAt: string;
};

export default function DashboardPage() {
  const [notes, setNotes] = useState<Note[]>([]);
  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchNotes = async () => {
    const res = await fetch('/api/notes');
    if (res.ok) setNotes(await res.json());
  };

  useEffect(() => {
    fetchNotes();
  }, []);

  const addNote = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/notes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title, content }),
      });
      if (!res.ok) throw new Error('Failed to add note');
      setTitle('');
      setContent('');
      await fetchNotes();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const summarize = async (id: string) => {
    const res = await fetch(`/api/notes/${id}/summarize`, { method: 'POST' });
    if (!res.ok) return;
    await fetchNotes();
  };

  return (
    <main className="mx-auto max-w-4xl p-6 space-y-6">
      <h1 className="text-2xl font-semibold">Your Notes</h1>
      <div className="border rounded p-4 space-y-3">
        <input className="w-full border rounded px-3 py-2" placeholder="Title" value={title} onChange={e => setTitle(e.target.value)} />
        <textarea className="w-full border rounded px-3 py-2 h-32" placeholder="Write or paste your notes..." value={content} onChange={e => setContent(e.target.value)} />
        {error && <p className="text-red-600 text-sm">{error}</p>}
        <button onClick={addNote} className="bg-blue-600 text-white rounded px-4 py-2" disabled={loading}>{loading ? 'Saving...' : 'Save Note'}</button>
      </div>
      <ul className="space-y-3">
        {notes.map(n => (
          <li key={n._id} className="border rounded p-4">
            <div className="flex items-center justify-between">
              <h2 className="font-medium">{n.title || 'Untitled'}</h2>
              <button onClick={() => summarize(n._id)} className="px-3 py-1 text-sm bg-emerald-600 text-white rounded">Summarize</button>
            </div>
            <p className="whitespace-pre-wrap text-sm text-gray-700 mt-2">{n.content}</p>
            {n.tags?.length > 0 && (
              <div className="mt-2 flex gap-2 flex-wrap">
                {n.tags.map(t => (
                  <span key={t} className="px-2 py-0.5 text-xs bg-gray-100 border rounded">{t}</span>
                ))}
              </div>
            )}
          </li>
        ))}
      </ul>
    </main>
  );
}

