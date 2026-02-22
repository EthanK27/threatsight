import mongoose from "mongoose";

const vulnNessusSchema = new mongoose.Schema(
  {
    reportId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Report",
      required: true,
      index: true,
    },
    host: { type: String, required: true },
    severity: { type: mongoose.Schema.Types.Mixed, required: true },
    cvssV3: { type: Number, default: null },
    vpr: { type: Number, default: null },
    epss: { type: Number, default: null },
    pluginId: { type: mongoose.Schema.Types.Mixed, required: true },
    name: { type: String, required: true },
    usn: { type: String, default: null },
    category: {
      type: String,
      enum: [
        "Patching",
        "Hardening",
        "Cryptography",
        "Authentication",
        "Exposure",
        "Application",
        "Disclosure",
        "Malware",
        "Compliance",
        "Other",
      ],
      default: "Other",
    },
  },
  { timestamps: true, versionKey: false }
);

export default mongoose.model("VulnNessus", vulnNessusSchema);
