import mongoose, { Schema, InferSchemaType, Model, Types } from 'mongoose';

const NoteSchema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    title: { type: String, default: '' },
    content: { type: String, default: '' },
    tags: { type: [String], default: [] },
  },
  { timestamps: true }
);

export type Note = InferSchemaType<typeof NoteSchema> & { _id: string; userId: Types.ObjectId };

export const NoteModel: Model<Note> =
  (mongoose.models.Note as Model<Note>) || mongoose.model<Note>('Note', NoteSchema);

