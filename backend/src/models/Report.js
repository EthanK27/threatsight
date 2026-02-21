import mongoose from "mongoose";

const reportSchema = new mongoose.Schema(
  {
    reportName: { type: String, required: true, trim: true },
    generatedAt: { type: Date, default: null },
    uploadedAt: { type: Date, default: Date.now },
    mode: { type: String, required: true, enum: ["Nessus", "Wireshark", "Honeypot"] },
  },
  { timestamps: true, versionKey: false }
);

export default mongoose.model("Report", reportSchema);