import https from 'https';
import fs from 'fs';
import crypto from 'crypto';
import readline from 'readline';

const DATA_URL = "https://huggingface.co/datasets/acnbartholomew/btp-agent-redteam-evals/raw/main/data/train-00000-of-00003.jsonl";
const OUTPUT_FILE = "audit_evidence/20261014_fullstack_validation/sample_500.jsonl";
const LIMIT = 500;

console.log(`Connecting to: ${DATA_URL}`);
const fileStream = fs.createWriteStream(OUTPUT_FILE);
let count = 0;

https.get(DATA_URL, (res) => {
  if (res.statusCode !== 200) {
    console.error(`HTTP Error: ${res.statusCode}`);
    process.exit(1);
  }

  const rl = readline.createInterface({ input: res, crlfDelay: Infinity });

  rl.on('line', (line) => {
    if (count < LIMIT) {
      fileStream.write(line + '\n');
      count++;
    } else {
      rl.close();
      res.destroy();
    }
  });

  rl.on('close', () => {
    fileStream.end(() => {
      const buffer = fs.readFileSync(OUTPUT_FILE);
      const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
      console.log(`Downloaded: ${count} vectors to ${OUTPUT_FILE}`);
      console.log(`File Size: ${buffer.length} bytes`);
      console.log(`SHA-256 Hash of sample_500.jsonl: ${sha256}`);
      fs.writeFileSync("audit_evidence/20261014_fullstack_validation/sample_500_hash.json", JSON.stringify({
        source_url: DATA_URL,
        hf_git_commit_sha: "cad39281ed9746dee40e5451239d784a8d32726b",
        file: OUTPUT_FILE,
        line_count: count,
        byte_length: buffer.length,
        sha256_hash: sha256,
        timestamp: new Date().toISOString()
      }, null, 2));
    });
  });
}).on('error', (err) => {
  console.error("Download failed:", err);
  process.exit(1);
});
