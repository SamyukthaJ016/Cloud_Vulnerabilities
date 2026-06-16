#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "../..");
const workspace = path.join(repoRoot, "outputs", "grc-compliance-governance-deck");
const slidesDir = path.join(workspace, "slides");
const previewDir = path.join(workspace, "previews");
const layoutDir = path.join(workspace, "layouts");
const finalPptx = path.join(__dirname, "grc-compliance-governance-slides.pptx");
const skillDir = "/Users/anjali/.codex/plugins/cache/openai-primary-runtime/presentations/26.601.10930/skills/presentations";
const buildScript = path.join(skillDir, "scripts", "build_artifact_deck.mjs");
const python = "/Users/anjali/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3";

const slideCount = 5;

const sharedModule = String.raw`
const T = {
  bg: "#F7FAF8",
  ink: "#10201C",
  muted: "#59726B",
  panel: "#FFFFFF",
  line: "#C8D8D2",
  green: "#0E7C66",
  green2: "#DDF4ED",
  cyan: "#0C7DAA",
  cyan2: "#E2F4FB",
  amber: "#B57900",
  amber2: "#FFF1D4",
  red: "#B83A3A",
  red2: "#FFE8E8",
  violet: "#6554C0",
  violet2: "#EEEAFE",
  dark: "#123C36"
};

function rect(slide, ctx, x, y, w, h, fill = T.panel, line = T.line) {
  return ctx.addShape(slide, {
    x, y, w, h,
    fill,
    line: { style: "solid", fill: line, width: 1 },
  });
}

function text(slide, ctx, value, x, y, w, h, opts = {}) {
  return ctx.addText(slide, {
    text: value,
    x, y, w, h,
    fontSize: opts.size ?? 18,
    color: opts.color ?? T.ink,
    bold: opts.bold ?? false,
    typeface: opts.face ?? (opts.bold ? ctx.fonts.title : ctx.fonts.body),
    align: opts.align ?? "left",
    valign: opts.valign ?? "top",
    fill: opts.fill ?? "#00000000",
    line: opts.line ?? { style: "solid", fill: "#00000000", width: 0 },
    insets: opts.insets ?? { left: 0, right: 0, top: 0, bottom: 0 },
  });
}

function base(slide, ctx, n) {
  rect(slide, ctx, 0, 0, ctx.W, ctx.H, T.bg, T.bg);
  rect(slide, ctx, 0, 0, 18, ctx.H, T.green, T.green);
  rect(slide, ctx, 18, 0, 5, ctx.H, T.amber, T.amber);
  text(slide, ctx, "Compliance and Governance | GRC + Cloud Scanner Evidence", 60, 670, 760, 20, { size: 12, color: T.muted });
  text(slide, ctx, String(n).padStart(2, "0") + " / 05", 1090, 670, 120, 20, { size: 12, color: T.muted, align: "right" });
}

function title(slide, ctx, kicker, heading, sub = "") {
  text(slide, ctx, kicker.toUpperCase(), 60, 40, 620, 24, { size: 13, bold: true, color: T.green });
  text(slide, ctx, heading, 60, 72, 980, 58, { size: 34, bold: true, color: T.ink });
  if (sub) text(slide, ctx, sub, 62, 132, 980, 40, { size: 16, color: T.muted });
}

function chip(slide, ctx, value, x, y, w, fill, color = T.ink) {
  rect(slide, ctx, x, y, w, 30, fill, fill);
  text(slide, ctx, value, x + 10, y + 8, w - 20, 14, { size: 11.5, bold: true, color, align: "center" });
}

function card(slide, ctx, x, y, w, h, heading, body, accent = T.green, fill = T.panel) {
  rect(slide, ctx, x, y, w, h, fill, T.line);
  rect(slide, ctx, x, y, 7, h, accent, accent);
  text(slide, ctx, heading, x + 20, y + 16, w - 36, 24, { size: 17, bold: true, color: accent });
  text(slide, ctx, body, x + 20, y + 48, w - 36, h - 62, { size: 12.5, color: T.muted });
}

function node(slide, ctx, label, sub, x, y, w, h, accent, fill = T.panel) {
  rect(slide, ctx, x, y, w, h, fill, accent);
  const compact = h <= 54;
  text(slide, ctx, label, x + 12, y + (compact ? 7 : 12), w - 24, compact ? 14 : 20, { size: compact ? 10.5 : 13.5, bold: true, color: accent, align: "center" });
  if (sub) text(slide, ctx, sub, x + 12, y + (compact ? 24 : 38), w - 24, compact ? h - 28 : h - 48, { size: compact ? 8.5 : 10.5, color: T.muted, align: "center" });
}

function bar(slide, ctx, x, y, w, h, color) {
  rect(slide, ctx, x, y, w, h, color, color);
}

function shape(slide, ctx, geometry, x, y, w, h, fill = T.line) {
  return ctx.addShape(slide, {
    geometry,
    x, y, w, h,
    fill,
    line: { style: "solid", fill, width: 0 },
  });
}

function hLine(slide, ctx, x1, y, x2, color = T.line) {
  bar(slide, ctx, Math.min(x1, x2), y - 1, Math.abs(x2 - x1), 3, color);
}

function vLine(slide, ctx, x, y1, y2, color = T.line) {
  bar(slide, ctx, x - 1, Math.min(y1, y2), 3, Math.abs(y2 - y1), color);
}

function hArrow(slide, ctx, x1, y, x2, color = T.line) {
  const dir = x2 >= x1 ? 1 : -1;
  const headW = 16;
  if (Math.abs(x2 - x1) > headW) {
    hLine(slide, ctx, x1, y, x2 - dir * headW, color);
  }
  shape(slide, ctx, dir > 0 ? "rightArrow" : "leftArrow", x2 - (dir > 0 ? headW : 0), y - 7, headW, 14, color);
}

function vArrowDown(slide, ctx, x, y1, y2, color = T.line) {
  const headH = 16;
  if (y2 - y1 > headH) {
    vLine(slide, ctx, x, y1, y2 - headH, color);
  }
  shape(slide, ctx, "downArrow", x - 7, y2 - headH, 14, headH, color);
}

function matrix(slide, ctx, x, y, cols, rows, widths, rowH = 46) {
  let xx = x;
  cols.forEach((c, i) => {
    rect(slide, ctx, xx, y, widths[i], 34, T.dark, T.dark);
    text(slide, ctx, c, xx + 8, y + 9, widths[i] - 16, 14, { size: 11.5, bold: true, color: "#FFFFFF" });
    xx += widths[i];
  });
  rows.forEach((row, r) => {
    xx = x;
    row.forEach((cell, i) => {
      rect(slide, ctx, xx, y + 34 + r * rowH, widths[i], rowH, r % 2 ? "#F0F7F4" : "#FFFFFF", T.line);
      text(slide, ctx, cell, xx + 8, y + 43 + r * rowH, widths[i] - 16, rowH - 14, { size: 10.5, color: i === 0 ? T.ink : T.muted, bold: i === 0 });
      xx += widths[i];
    });
  });
}

export async function buildSlide(presentation, ctx, n) {
  const slide = presentation.slides.add();
  base(slide, ctx, n);

  if (n === 1) {
    text(slide, ctx, "Compliance and Governance", 60, 72, 780, 58, { size: 42, bold: true, color: T.ink });
    text(slide, ctx, "GRC layer powered by scanner evidence", 62, 135, 720, 38, { size: 24, bold: true, color: T.green });
    text(slide, ctx, "Converts cloud, infrastructure, web app, identity, monitoring, and DPDP evidence into control status, risk ownership, remediation tracking, and audit-ready reports.", 64, 205, 760, 64, { size: 18, color: T.muted });
    chip(slide, ctx, "CloudGuard", 64, 305, 120, T.green2, T.green);
    chip(slide, ctx, "Generic GRC", 198, 305, 120, T.cyan2, T.cyan);
    chip(slide, ctx, "DPDP / ISO / CIS / NIST", 332, 305, 190, T.amber2, T.amber);
    chip(slide, ctx, "Audit Evidence", 536, 305, 140, T.violet2, T.violet);
    card(slide, ctx, 64, 405, 250, 128, "Purpose", "Single governance view for compliance posture, risk, evidence, ownership, and exceptions.", T.green);
    card(slide, ctx, 354, 405, 250, 128, "Technical proof", "CloudGuard scanner evidence from AWS, GCP, Kubernetes, IaC, and vulnerability tools.", T.cyan);
    card(slide, ctx, 644, 405, 250, 128, "Outcome", "Control-mapped findings that teams can remediate and auditors can verify.", T.amber);
    rect(slide, ctx, 930, 95, 235, 385, "#102C27", "#102C27");
    text(slide, ctx, "Assigned topic", 965, 120, 165, 20, { size: 13, bold: true, color: "#8AF0D2", align: "center" });
    text(slide, ctx, "GRC and Cloud Scanners", 955, 178, 186, 88, { size: 23, bold: true, color: "#FFFFFF", align: "center" });
    text(slide, ctx, "Inputs from Ishaan's GRC and cloud scanner work", 965, 345, 165, 58, { size: 13, color: "#BFE8DE", align: "center" });
    return slide;
  }

  if (n === 2) {
    title(slide, ctx, "GRC Role", "What the governance layer should own", "A GRC platform becomes useful when it links controls to live evidence and accountable remediation.");
    const items = [
      ["Policies and controls", "ISO 27001, CIS, NIST, OWASP, Kubernetes, DPDP and internal controls.", T.green],
      ["Risk register", "Severity, likelihood, impact, owner, due date, exception and residual risk.", T.amber],
      ["Evidence management", "Raw artifacts, scanner findings, screenshots, logs, approvals and timestamps.", T.cyan],
      ["Audit and reporting", "Control status, evidence trail, remediation proof and executive summaries.", T.violet]
    ];
    items.forEach((it, i) => card(slide, ctx, 75 + (i % 2) * 535, 218 + Math.floor(i / 2) * 150, 445, 108, it[0], it[1], it[2]));
    matrix(slide, ctx, 150, 535, ["Input", "GRC Output"], [
      ["Finding", "Control status and risk"],
      ["Evidence", "Audit proof"],
      ["Remediation", "Owner and closure status"]
    ], [240, 630], 30);
    return slide;
  }

  if (n === 3) {
    title(slide, ctx, "Architecture", "Evidence pipeline into GRC", "Every source sends normalized evidence; the GRC layer maps it to controls, risk and remediation.");
    const sources = [
      ["LogManthan", "Monitoring / threat intel", T.green],
      ["Omjee + Vivek", "Infra scanner findings", T.cyan],
      ["Asset inventory", "Manual + scanner inputs", T.amber],
      ["SAST / DAST / Burp", "Web application security", T.red],
      ["Keycloak / IAM", "Identity and access controls", T.violet],
      ["DPDP inputs", "Privacy evidence", T.green]
    ];
    sources.forEach((s, i) => node(slide, ctx, s[0], s[1], 70, 202 + i * 58, 210, 42, s[2], "#FFFFFF"));
    node(slide, ctx, "Connector Layer", "Normalize schema, source, severity, owner, tenant/user context", 345, 270, 210, 112, T.green, T.green2);
    node(slide, ctx, "Evidence Ingestion API", "Validate payload, checksum and auth token", 610, 270, 210, 112, T.cyan, T.cyan2);
    node(slide, ctx, "Storage Layer", "PostgreSQL metadata + object storage artifacts", 875, 270, 210, 112, T.amber, T.amber2);
    node(slide, ctx, "GRC Dashboard", "Controls, risk, evidence, remediation, audit reports", 610, 455, 270, 92, T.violet, T.violet2);
    vLine(slide, ctx, 305, 223, 513, T.line);
    [223, 281, 339, 397, 455, 513].forEach((y) => hLine(slide, ctx, 280, y, 305, T.line));
    hArrow(slide, ctx, 305, 326, 345, T.line);
    hArrow(slide, ctx, 555, 326, 610, T.line);
    hArrow(slide, ctx, 820, 326, 875, T.line);
    vLine(slide, ctx, 980, 382, 430, T.line);
    hLine(slide, ctx, 980, 430, 745, T.line);
    vArrowDown(slide, ctx, 745, 430, 455, T.line);
    text(slide, ctx, "CloudGuard scanners feed the same pipeline for AWS, GCP, Kubernetes and IaC evidence.", 365, 205, 660, 28, { size: 15, bold: true, color: T.dark, align: "center" });
    return slide;
  }

  if (n === 4) {
    title(slide, ctx, "Setup", "Docker/Dokploy PoC deployment model", "The GRC and scanner services can run as separate Docker services while Dokploy handles HTTPS, domains and logs.");
    node(slide, ctx, "app.cloudscanner.com", "Dashboard / GRC portal", 70, 220, 190, 62, T.green, T.green2);
    node(slide, ctx, "api.cloudscanner.com", "Backend APIs", 70, 315, 190, 62, T.cyan, T.cyan2);
    node(slide, ctx, "ingest.cloudscanner.com", "Evidence ingestion", 70, 410, 190, 62, T.amber, T.amber2);
    node(slide, ctx, "Dokploy / Traefik", "HTTPS, domains, deploys, logs", 335, 315, 210, 92, T.dark, "#E8F7F2");
    node(slide, ctx, "Backend Service", "FastAPI UI + API + GRC endpoints", 620, 315, 210, 92, T.green, "#FFFFFF");
    node(slide, ctx, "PostgreSQL", "Findings, jobs, evidence metadata", 910, 245, 210, 76, T.cyan, "#FFFFFF");
    node(slide, ctx, "Object Storage", "Raw evidence artifacts", 910, 365, 210, 76, T.amber, "#FFFFFF");
    node(slide, ctx, "Scheduler Worker", "Creates scheduled scan jobs", 365, 500, 210, 66, T.violet, "#FFFFFF");
    node(slide, ctx, "Scan Worker", "Polls jobs and writes results", 650, 500, 210, 66, T.red, "#FFFFFF");
    node(slide, ctx, "Evidence Connector", "Posts normalized evidence", 935, 500, 210, 66, T.green, "#FFFFFF");

    vLine(slide, ctx, 290, 251, 441, T.line);
    [251, 346, 441].forEach((y) => hLine(slide, ctx, 260, y, 290, T.line));
    hArrow(slide, ctx, 290, 361, 335, T.line);
    hArrow(slide, ctx, 545, 361, 620, T.line);
    vLine(slide, ctx, 725, 407, 500, T.line);
    hLine(slide, ctx, 830, 361, 870, T.line);
    vLine(slide, ctx, 870, 283, 403, T.line);
    hArrow(slide, ctx, 870, 283, 910, T.line);
    hArrow(slide, ctx, 870, 403, 910, T.line);
    hArrow(slide, ctx, 575, 533, 650, T.line);
    hArrow(slide, ctx, 860, 533, 935, T.line);
    vLine(slide, ctx, 1015, 441, 500, T.line);
    text(slide, ctx, "PoC VM: 4 vCPU / 8 GB RAM / 100 GB SSD recommended for scanner-heavy demos.", 110, 575, 960, 26, { size: 18, bold: true, color: T.dark, align: "center" });
    return slide;
  }

  if (n === 5) {
    title(slide, ctx, "Outputs", "What we can send as relevant details", "The GRC topic should show business value and technical implementation together.");
    matrix(slide, ctx, 70, 205, ["Area", "Details to include", "Owner / input"], [
      ["Compliance dashboard", "Control status, evidence count, non-compliance, risk owner, remediation status", "GRC + CloudGuard"],
      ["Cloud scanner evidence", "AWS, GCP, Kubernetes, IaC, vulnerability/dependency findings", "Ishaan / Cloud scanners"],
      ["Identity controls", "SSO, MFA, RBAC, lifecycle, audit logs using open-source Keycloak-style IAM", "Identity stream"],
      ["DPDP governance", "Consent, access control, audit evidence, privacy evidence mapping", "Pratik / Shaswati"],
      ["Integrations", "LogManthan, infra scanner, asset inventory, SAST, DAST/Burp via connectors", "All topic owners"]
    ], [210, 620, 260], 54);
    card(slide, ctx, 145, 532, 920, 86, "Recommendation", "Use the GRC layer as the common reporting layer: scanners and teams produce evidence, connectors normalize it, and the dashboard maps it to controls and remediation.", T.green, T.green2);
    return slide;
  }

  return slide;
}
`;

async function main() {
  await fs.rm(workspace, { recursive: true, force: true });
  await fs.mkdir(slidesDir, { recursive: true });
  await fs.mkdir(previewDir, { recursive: true });
  await fs.mkdir(layoutDir, { recursive: true });
  await fs.writeFile(path.join(slidesDir, "deck-utils.mjs"), sharedModule, "utf8");

  for (let i = 1; i <= slideCount; i += 1) {
    const padded = String(i).padStart(2, "0");
    await fs.writeFile(
      path.join(slidesDir, `slide-${padded}.mjs`),
      `import { buildSlide } from "./deck-utils.mjs";\n\nexport async function slide${padded}(presentation, ctx) {\n  return buildSlide(presentation, ctx, ${i});\n}\n`,
      "utf8"
    );
  }

  const result = spawnSync(
    process.execPath,
    [
      buildScript,
      "--workspace", workspace,
      "--slides-dir", slidesDir,
      "--out", finalPptx,
      "--preview-dir", previewDir,
      "--layout-dir", layoutDir,
      "--contact-sheet", path.join(previewDir, "contact-sheet.png"),
      "--manifest", path.join(workspace, "artifact-build-manifest.json"),
      "--slide-count", String(slideCount)
    ],
    {
      cwd: repoRoot,
      env: { ...process.env, PYTHON: python },
      encoding: "utf8"
    }
  );

  if (result.status !== 0) {
    console.error(result.stdout);
    console.error(result.stderr);
    process.exit(result.status ?? 1);
  }

  await fs.copyFile(path.join(previewDir, "slide-03.png"), path.join(__dirname, "architecture-grc-evidence-flow.png"));
  await fs.copyFile(path.join(previewDir, "slide-04.png"), path.join(__dirname, "setup-dokploy-cloudguard-stack.png"));

  console.log(result.stdout);
  console.log(JSON.stringify({
    finalPptx,
    architectureImage: path.join(__dirname, "architecture-grc-evidence-flow.png"),
    setupImage: path.join(__dirname, "setup-dokploy-cloudguard-stack.png"),
    contactSheet: path.join(previewDir, "contact-sheet.png")
  }, null, 2));
}

main().catch((error) => {
  console.error(error.stack || error.message || String(error));
  process.exit(1);
});
