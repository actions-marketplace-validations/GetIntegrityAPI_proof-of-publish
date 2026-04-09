import fs from "fs";
import crypto from "crypto";
import path from "path";
import axios from "axios";
import PDFDocument from "pdfkit";

/* -----------------------------
Helper utilities
------------------------------*/

function mustGetEnv(name, fallback = "") {
  const v = process.env[name] ?? fallback;
  return v && String(v).trim() ? String(v).trim() : "";
}

function writeGithubOutput(key, value) {
  const outFile = process.env.GITHUB_OUTPUT;
  if (!outFile) return;
  fs.appendFileSync(outFile, `${key}=${String(value).replace(/\r?\n/g, " ")}\n`);
}

function sha256File(filePath) {
  const buf = fs.readFileSync(filePath);
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function safeString(v) {
  if (v === undefined || v === null) return "";
  if (typeof v === "string") return v;

  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}

function boolLabel(v) {
  return v === true ? "Yes" : v === false ? "No" : "";
}

/* -----------------------------
PDF Receipt Renderer
------------------------------*/

function renderReceiptPdf(pdfPath, receipt, receiptHash) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: "A4", margin: 48 });
    const stream = fs.createWriteStream(pdfPath);

    stream.on("finish", resolve);
    stream.on("error", reject);

    doc.pipe(stream);

    const proofResponse = receipt?.proof_response || {};
    const capsule = proofResponse?.capsule || {};
    const lineage = proofResponse?.lineage || {};
    const gh = receipt?.github_context || {};

    const verified =
      proofResponse?.verified === true || proofResponse?.verified === "true";

    const validator = safeString(capsule.validator || proofResponse.validator);
    const latencyMs = safeString(proofResponse.latency_ms);

    function sectionTitle(title) {
      doc.moveDown(0.25);
      doc.fontSize(14).text(title);
      doc.moveDown(0.25);
      doc.fontSize(11);
    }

    function writeField(label, value, options = {}) {
      const text = safeString(value);
      if (!text) return;
      doc.text(`${label}: ${text}`, {
        width: 499,
        ...options,
      });
    }

    // Header
    doc.fontSize(22).text("GetIntegrityAPI - Publish Proof Receipt");
    doc.moveDown(0.5);

    doc.fontSize(12).text(`Status: ${verified ? "VERIFIED" : "UNVERIFIED"}`);
    doc.moveDown(0.5);

    doc.fontSize(11);
    writeField("Receipt Version", receipt.receipt_version || "1");
    writeField("Proof ID", receipt.proof_id);
    writeField("Issued At", receipt.issued_at);
    writeField("Validator", validator);
    writeField("Verified", verified ? "true" : "false");
    writeField("Latency (ms)", latencyMs);

    doc.moveDown(0.5);
    doc.text(`Receipt URL: ${safeString(receipt.receipt_url)}`, {
      link: safeString(receipt.receipt_url),
      underline: true,
      width: 499,
    });

    doc.moveDown(0.5);
    doc.moveTo(48, doc.y).lineTo(547, doc.y).stroke();
    doc.moveDown(0.75);

    // GitHub context
    sectionTitle("GitHub Context");
    writeField("Repository", gh.repository);
    writeField("Commit", gh.commit);
    writeField("Actor", gh.actor);
    writeField("Workflow", gh.workflow);
    writeField("Run ID", gh.run_id);
    writeField("Run Number", gh.run_number);
    writeField("Ref", gh.ref);

    // Capsule summary
    doc.moveDown(0.75);
    sectionTitle("Cryptographic Capsule Summary");
    writeField("Algorithm", capsule.alg);
    writeField("Key ID (kid)", capsule.kid);
    writeField("HP Version", capsule.hp_version);
    writeField("Capsule Timestamp", capsule.timestamp);
    writeField("Capsule Digest", capsule.digest);
    writeField("Signature", capsule.signature);

    // Lineage summary
    if (
      lineage.seq !== undefined ||
      lineage.prev_chain_digest !== undefined ||
      lineage.chain_digest !== undefined
    ) {
      doc.moveDown(0.75);
      sectionTitle("Lineage Summary");
      writeField("Sequence", lineage.seq);
      writeField("Previous Chain Digest", lineage.prev_chain_digest);
      writeField("Chain Digest", lineage.chain_digest);
    }

    // Offline verification
    doc.moveDown(0.75);
    sectionTitle("Offline Verification");
    doc.text("1) Compute SHA256 of receipt.json");
    doc.text("2) Compare with receipt.sha256");
    doc.text("3) Verify the signed capsule using the published public key material");
    doc.moveDown(0.25);
    writeField("Receipt SHA256", receiptHash);

    doc.moveDown(0.75);
    doc.fontSize(10).text(
      "This PDF is a human-readable summary of receipt.json. The canonical evidence artifact is receipt.json, and offline integrity verification is performed by hashing receipt.json and comparing it to receipt.sha256."
    );

    doc.end();
  });
}

/* -----------------------------
Main Action
------------------------------*/

async function run() {
  try {
    const apiKey = mustGetEnv("GI_API_KEY");

    if (!apiKey) {
      console.error("GI_API_KEY is required");
      process.exit(1);
    }

    const workspace = mustGetEnv("GITHUB_WORKSPACE", process.cwd());

    if (!fs.existsSync(workspace)) {
      throw new Error(`Workspace directory does not exist: ${workspace}`);
    }

    console.log("Workspace resolved to:", workspace);

    const payload = {
      event: "github_publish",
      repository: mustGetEnv("GITHUB_REPOSITORY"),
      commit: mustGetEnv("GITHUB_SHA"),
      actor: mustGetEnv("GITHUB_ACTOR"),
      run_id: mustGetEnv("GITHUB_RUN_ID"),
      run_number: mustGetEnv("GITHUB_RUN_NUMBER"),
      workflow: mustGetEnv("GITHUB_WORKFLOW"),
      ref: mustGetEnv("GITHUB_REF"),
      timestamp: new Date().toISOString(),
    };

    const response = await axios.post(
      "https://api.getintegrityapi.com/proof",
      payload,
      {
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
          "User-Agent": "getintegrityapi-github-action",
        },
        timeout: 15000,
      }
    );

    if (!response?.data?.proof_id) {
      throw new Error("Invalid response from proof endpoint (missing proof_id)");
    }

    const proofId = response.data.proof_id;
    const receiptUrl = response.data.receipt_url;

    const receipt = {
      receipt_version: "1",
      proof_id: proofId,
      receipt_url: receiptUrl,
      issued_at: new Date().toISOString(),
      github_context: payload,
      proof_response: response.data,
    };

    const receiptPath = path.join(workspace, "receipt.json");
    const hashPath = path.join(workspace, "receipt.sha256");
    const pdfPath = path.join(workspace, "receipt.pdf");

    // Write receipt.json
    fs.writeFileSync(receiptPath, JSON.stringify(receipt, null, 2), "utf8");

    // Compute hash of canonical evidence artifact
    const receiptHash = sha256File(receiptPath);
    fs.writeFileSync(hashPath, receiptHash + "\n", "utf8");

    // Render PDF summary
    await renderReceiptPdf(pdfPath, receipt, receiptHash);

    console.log("Proof ID:", proofId);
    console.log("Receipt URL:", receiptUrl);
    console.log("Receipt SHA256:", receiptHash);
    console.log("Receipt written to:", receiptPath);
    console.log("Hash written to:", hashPath);
    console.log("PDF written to:", pdfPath);

    // GitHub outputs
    writeGithubOutput("proof_id", proofId);
    writeGithubOutput("receipt_url", receiptUrl);
    writeGithubOutput("receipt_sha256", receiptHash);
    writeGithubOutput("receipt_json_path", receiptPath);
    writeGithubOutput("receipt_sha256_path", hashPath);
    writeGithubOutput("receipt_pdf_path", pdfPath);
  } catch (error) {
    const message =
      error?.response?.data?.error ||
      error?.response?.data?.message ||
      error?.message ||
      String(error);

    console.error("Proof generation failed:", message);
    process.exit(1);
  }
}

/* -----------------------------
Execute
------------------------------*/

run();
