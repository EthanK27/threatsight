import express from "express";
import cors from "cors";
import reportRoutes from "./routes/reportRoutes.js";
import analysisRoutes from "./routes/analysisRoutes.js";

const PORT = process.env.PORT || 3001;
const app = express();

app.use(cors());
app.use(express.json());
app.use("/api/analysis", analysisRoutes);

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
app.get("/health", (req, res) => res.status(200).json({ ok: true, service: "backend" }));

app.use("/api/reports", reportRoutes);

// error handler (multer + general)
app.use((err, _req, res, _next) => {
    console.error(err);
    res.status(400).json({ error: err.message || "Request failed" });
});

export default app;