import app from "./app.js";
import { connectDB } from "./config/db.js";
import { PORT } from "./config/env.js";

try {
  await connectDB();
  app.listen(PORT, () => console.log(`API listening on ${PORT}`));
} catch (err) {
  console.error("Startup error:", err);
  process.exit(1);
}