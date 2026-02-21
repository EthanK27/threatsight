import express from "express";
import cors from "cors";
import reportRoutes from "./routes/reportRoutes.js";
import analysisRoutes from "./routes/analysisRoutes.js";

const app = express();

app.use(cors());
app.use(express.json());
app.use("/api/analysis", analysisRoutes);


app.get("/health", (req, res) => res.json({ ok: true }));

app.use("/api/reports", reportRoutes);

export default app;