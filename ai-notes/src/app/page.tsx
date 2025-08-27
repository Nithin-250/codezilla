import Link from 'next/link';

export default function HomePage() {
  return (
    <main className="mx-auto max-w-2xl p-6">
      <h1 className="text-3xl font-bold mb-4">AI Notes</h1>
      <p className="text-gray-700 mb-6">Summarize, organize, and enhance your notes with AI.</p>
      <div className="flex gap-3">
        <Link href="/login" className="px-4 py-2 bg-blue-600 text-white rounded">Login</Link>
        <Link href="/register" className="px-4 py-2 border border-gray-300 rounded">Register</Link>
      </div>
    </main>
  );
}

