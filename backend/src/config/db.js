import mongoose from "mongoose";

export async function connectDB() {
  if (!process.env.MONGODB_URI) throw new Error("Missing MONGODB_URI in env");
  mongoose.set("strictQuery", true);
  await mongoose.connect(process.env.MONGODB_URI);
  console.log("MongoDB connected");
}