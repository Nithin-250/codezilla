import mongoose from 'mongoose';

const MONGODB_URI = process.env.MONGODB_URI || '';

if (!MONGODB_URI) {
  console.warn('MONGODB_URI not set');
}

let isConnected = false as boolean;

export async function connectToDatabase(): Promise<typeof mongoose> {
  if (isConnected && mongoose.connection.readyState === 1) {
    return mongoose;
  }
  if (mongoose.connection.readyState === 1) {
    isConnected = true;
    return mongoose;
  }
  await mongoose.connect(MONGODB_URI, { dbName: 'ai-notes' });
  isConnected = true;
  return mongoose;
}

