import express from "express";
import cors from "cors";
import reportRoutes from "./routes/reportRoutes.js";

const app = express();

app.use(cors());
app.use(express.json());


app.get("/health", (req, res) => res.json({ ok: true }));

app.use("/api/reports", reportRoutes);

export default app;