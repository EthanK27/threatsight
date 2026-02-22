import mongoose from "mongoose";

const vulnWiresharkSchema = new mongoose.Schema(
  {
    reportId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Report",
      required: true,
      index: true,
    },

    timestamp: { type: Date, required: true },
    SrcIP: { type: String, required: true },
    DestIP: { type: String, required: true },
    Protocol: { type: String, required: true },
    Info: { type: String, required: true },
  },
  {
    timestamps: true,
    versionKey: false,
    collection: "vulnwiresharks",
  }
);

export default mongoose.model("VulnWireshark", vulnWiresharkSchema);
