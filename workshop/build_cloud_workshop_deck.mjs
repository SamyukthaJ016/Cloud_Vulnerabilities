#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const workspace = path.join(repoRoot, "outputs", "cloud-workshop-deck");
const slidesDir = path.join(workspace, "slides");
const previewDir = path.join(workspace, "previews");
const layoutDir = path.join(workspace, "layouts");
const qaDir = path.join(workspace, "qa");
const finalPptx = path.join(__dirname, "cloud-attack-paths-workshop-slides.pptx");
const skillDir = "/Users/anjali/.codex/plugins/cache/openai-primary-runtime/presentations/26.601.10930/skills/presentations";
const buildScript = path.join(skillDir, "scripts", "build_artifact_deck.mjs");
const python = "/Users/anjali/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3";

const slideCount = 24;

const sharedModule = String.raw`
const T = {
  bg: "#07110F",
  bg2: "#0D1714",
  panel: "#101F1B",
  panel2: "#132924",
  ink: "#F4F8F7",
  muted: "#9DB5AE",
  faint: "#20372F",
  line: "#315348",
  green: "#38D39F",
  cyan: "#38BDF8",
  amber: "#F5B84B",
  red: "#F87171",
  violet: "#A78BFA",
  white: "#FFFFFF"
};

function rect(slide, ctx, x, y, w, h, fill = T.panel, line = T.line, name) {
  return ctx.addShape(slide, {
    x, y, w, h,
    fill,
    line: { style: "solid", fill: line, width: 1 },
    name
  });
}

function text(slide, ctx, value, x, y, w, h, opts = {}) {
  return ctx.addText(slide, {
    text: value,
    x, y, w, h,
    fontSize: opts.size ?? 22,
    color: opts.color ?? T.ink,
    bold: opts.bold ?? false,
    typeface: opts.face ?? (opts.bold ? ctx.fonts.title : ctx.fonts.body),
    align: opts.align ?? "left",
    valign: opts.valign ?? "top",
    fill: opts.fill ?? "#00000000",
    line: opts.line ?? { style: "solid", fill: "#00000000", width: 0 },
    insets: opts.insets ?? { left: 0, right: 0, top: 0, bottom: 0 },
    name: opts.name
  });
}

function line(slide, ctx, x, y, w, h, color = T.green) {
  return ctx.addShape(slide, {
    x, y, w, h,
    fill: color,
    line: { style: "solid", fill: color, width: 0 },
    geometry: "rect"
  });
}

function base(slide, ctx, label = "") {
  rect(slide, ctx, 0, 0, ctx.W, ctx.H, T.bg, T.bg);
  rect(slide, ctx, 0, 0, 18, ctx.H, T.green, T.green);
  rect(slide, ctx, 18, 0, 4, ctx.H, T.cyan, T.cyan);
  line(slide, ctx, 72, 650, 1080, 1, T.faint);
  text(slide, ctx, "Cloud Attack Paths and Evidence-Driven Defense", 72, 666, 620, 20, { size: 12, color: T.muted });
  text(slide, ctx, label, 1030, 666, 150, 20, { size: 12, color: T.muted, align: "right" });
}

function title(slide, ctx, kicker, heading, sub = "") {
  if (kicker) text(slide, ctx, kicker.toUpperCase(), 72, 42, 620, 26, { size: 14, color: T.green, bold: true });
  text(slide, ctx, heading, 72, 74, 980, 70, { size: 38, color: T.ink, bold: true });
  if (sub) text(slide, ctx, sub, 74, 145, 940, 42, { size: 18, color: T.muted });
}

function chip(slide, ctx, value, x, y, w, color = T.green) {
  rect(slide, ctx, x, y, w, 30, "#0B1815", color);
  text(slide, ctx, value, x + 12, y + 7, w - 24, 16, { size: 12, color, bold: true, align: "center" });
}

function bulletList(slide, ctx, items, x, y, w, opts = {}) {
  const gap = opts.gap ?? 44;
  items.forEach((item, i) => {
    const yy = y + i * gap;
    rect(slide, ctx, x, yy + 7, 10, 10, opts.color ?? T.green, opts.color ?? T.green);
    text(slide, ctx, item, x + 24, yy, w - 24, gap - 4, { size: opts.size ?? 18, color: opts.textColor ?? T.ink });
  });
}

function card(slide, ctx, x, y, w, h, heading, body, accent = T.green) {
  rect(slide, ctx, x, y, w, h, T.panel, T.line);
  line(slide, ctx, x, y, w, 5, accent);
  const compact = h < 110;
  text(slide, ctx, heading, x + 18, y + (compact ? 16 : 18), w - 36, compact ? 22 : 30, { size: compact ? 14 : 19, bold: true, color: T.ink });
  text(slide, ctx, body, x + 18, y + (compact ? 42 : 56), w - 36, h - (compact ? 58 : 70), { size: compact ? 11.5 : 14, color: T.muted });
}

function miniCard(slide, ctx, x, y, w, h, heading, body, accent = T.green) {
  rect(slide, ctx, x, y, w, h, T.panel2, T.line);
  rect(slide, ctx, x + 14, y + 16, 10, 10, accent, accent);
  text(slide, ctx, heading, x + 34, y + 12, w - 44, 24, { size: 15, bold: true, color: T.ink });
  text(slide, ctx, body, x + 34, y + 38, w - 48, h - 48, { size: 12, color: T.muted });
}

function metric(slide, ctx, value, label, x, y, w, accent) {
  rect(slide, ctx, x, y, w, 92, "#0B1815", T.line);
  text(slide, ctx, value, x + 14, y + 14, w - 28, 36, { size: 28, bold: true, color: accent });
  text(slide, ctx, label, x + 14, y + 52, w - 28, 28, { size: 13, color: T.muted });
}

function stage(slide, ctx, index, heading, body, x, y, w, accent) {
  rect(slide, ctx, x, y, w, 98, T.panel, T.line);
  rect(slide, ctx, x + 14, y + 16, 28, 28, accent, accent);
  text(slide, ctx, String(index), x + 14, y + 21, 28, 14, { size: 14, bold: true, color: "#05100E", align: "center" });
  text(slide, ctx, heading, x + 54, y + 15, w - 68, 23, { size: 15, bold: true });
  text(slide, ctx, body, x + 54, y + 42, w - 68, 38, { size: 11.5, color: T.muted });
}

function matrix(slide, ctx, x, y, cols, rows, widths, rowH = 52) {
  let xx = x;
  cols.forEach((c, i) => {
    rect(slide, ctx, xx, y, widths[i], 38, "#14382E", T.line);
    text(slide, ctx, c, xx + 10, y + 10, widths[i] - 20, 16, { size: 12, bold: true, color: T.green });
    xx += widths[i];
  });
  rows.forEach((row, r) => {
    xx = x;
    row.forEach((cell, i) => {
      rect(slide, ctx, xx, y + 38 + r * rowH, widths[i], rowH, r % 2 ? "#0E1B18" : T.panel, T.line);
      text(slide, ctx, cell, xx + 10, y + 48 + r * rowH, widths[i] - 20, rowH - 16, { size: 11.5, color: i === 0 ? T.ink : T.muted, bold: i === 0 });
      xx += widths[i];
    });
  });
}

function providerBand(slide, ctx, provider, items, x, y, w, accent) {
  rect(slide, ctx, x, y, w, 72, T.panel, T.line);
  line(slide, ctx, x, y, 5, 72, accent);
  text(slide, ctx, provider, x + 18, y + 16, 120, 24, { size: 17, bold: true, color: accent });
  text(slide, ctx, items, x + 150, y + 16, w - 170, 40, { size: 13, color: T.muted });
}

export async function buildSlide(presentation, ctx, n) {
  const slide = presentation.slides.add();
  base(slide, ctx, String(n).padStart(2, "0") + " / 24");

  if (n === 1) {
    text(slide, ctx, "Cloud Attack Paths", 72, 92, 820, 72, { size: 56, bold: true, color: T.ink });
    text(slide, ctx, "and Evidence-Driven Defense", 74, 164, 870, 60, { size: 42, bold: true, color: T.green });
    text(slide, ctx, "A two-day lab workshop for multi-cloud security, scanner validation, tenant-aware evidence, and compliance-ready remediation.", 76, 252, 720, 58, { size: 20, color: T.muted });
    chip(slide, ctx, "AWS", 76, 340, 84, T.amber);
    chip(slide, ctx, "Azure", 172, 340, 92, T.cyan);
    chip(slide, ctx, "GCP", 276, 340, 82, T.green);
    chip(slide, ctx, "DigitalOcean", 370, 340, 136, T.violet);
    chip(slide, ctx, "Kubernetes", 518, 340, 128, T.red);
    const stages = ["Exposed asset", "Identity abuse", "Data access", "Runtime pivot", "Evidence and fix"];
    stages.forEach((s, i) => {
      const x = 78 + i * 210;
      stage(slide, ctx, i + 1, s, ["Find weak entry", "Map permissions", "Verify impact", "Trace blast radius", "Prove remediation"][i], x, 465, 180, i % 2 ? T.cyan : T.green);
      if (i < 4) line(slide, ctx, x + 182, 507, 26, 3, T.line);
    });
    return slide;
  }

  if (n === 2) {
    title(slide, ctx, "Scope", "Public reference, original workshop", "We use the public training page as a scope signal, then build our own authorized internal curriculum around scanner evidence and dashboard outcomes.");
    card(slide, ctx, 78, 215, 340, 290, "Public page signals", "Two-day, hands-on, intermediate-to-advanced multi-cloud security training. The published outline mentions recon, SSRF and metadata, serverless, data tier, containers, Kubernetes, IAM, AI integrations, developer platforms, and defenses.", T.cyan);
    card(slide, ctx, 470, 215, 340, 290, "Our version", "Lab-safe, tenant-aware, and tied to our project. Every exercise produces normalized evidence that flows through connectors into the compliance dashboard.", T.green);
    card(slide, ctx, 862, 215, 300, 290, "What changes", "We add CloudGuard scanner validation, IaC file uploads, kubeconfig scanning, evidence processors, tenant_id segregation, and executive-ready reporting.", T.amber);
    return slide;
  }

  if (n === 3) {
    title(slide, ctx, "Outcomes", "What participants should be able to do", "The workshop is designed around useful operational skills, not just cloud trivia.");
    card(slide, ctx, 78, 210, 250, 230, "Find", "Read cloud exposure, IAM, runtime, Kubernetes, and IaC evidence quickly.", T.green);
    card(slide, ctx, 358, 210, 250, 230, "Prove", "Collect artifacts and scanner output that supports an audit-ready finding.", T.cyan);
    card(slide, ctx, 638, 210, 250, 230, "Fix", "Map each issue to an owner, control, blast radius, and remediation path.", T.amber);
    card(slide, ctx, 918, 210, 250, 230, "Standardize", "Emit normalized evidence with tenant_id so every scanner follows the same contract.", T.violet);
    metric(slide, ctx, "2 days", "Instructor-led practical labs", 78, 500, 180, T.green);
    metric(slide, ctx, "4 scanners", "AWS, GCP, Kubernetes, IaC", 285, 500, 210, T.cyan);
    metric(slide, ctx, "1 capstone", "End-to-end evidence workflow", 522, 500, 230, T.amber);
    metric(slide, ctx, "tenant_id", "Mandatory segregation key", 780, 500, 220, T.violet);
    return slide;
  }

  if (n === 4) {
    title(slide, ctx, "Rules", "Authorized labs only", "Every lab is isolated, logged, budgeted, and intentionally vulnerable.");
    const items = [
      ["Approved scope", "Use only instructor-provided accounts, lab tenants, local clusters, or disposable projects."],
      ["No real secrets", "Credentials are lab-only. Raw secrets must never be stored in findings or reports."],
      ["Least privilege", "Scanner credentials are scoped by tenant and scanner type."],
      ["Cleanup first", "Budgets, teardown scripts, and credential rotation are part of the exercise."]
    ];
    items.forEach((it, i) => miniCard(slide, ctx, 92 + (i % 2) * 520, 225 + Math.floor(i / 2) * 150, 450, 112, it[0], it[1], [T.green, T.cyan, T.amber, T.red][i]));
    text(slide, ctx, "Workshop mantra", 92, 550, 180, 24, { size: 14, color: T.green, bold: true });
    text(slide, ctx, "If it is not owned, isolated, and approved, it is not a workshop target.", 92, 582, 920, 36, { size: 24, bold: true });
    return slide;
  }

  if (n === 5) {
    title(slide, ctx, "Mental Model", "Cloud breaches are chains", "The useful unit of analysis is the path from exposure to impact.");
    const stages = [
      ["Discover", "DNS, assets, repos, artifacts"],
      ["Foothold", "Public service, token, weak config"],
      ["Identity", "Role, service account, managed identity"],
      ["Pivot", "Runtime, serverless, data tier, cluster"],
      ["Control", "Data access or control-plane action"],
      ["Evidence", "Scanner result, artifact, control map"]
    ];
    stages.forEach((s, i) => {
      const x = 75 + i * 185;
      stage(slide, ctx, i + 1, s[0], s[1], x, 280, 160, [T.green, T.cyan, T.amber, T.violet, T.red, T.green][i]);
      if (i < stages.length - 1) line(slide, ctx, x + 162, 322, 20, 3, T.line);
    });
    card(slide, ctx, 92, 475, 1020, 90, "Why this matters", "Scanner findings are easier to prioritize when they are attached to an attack path: entry point, identity, reachable data, blast radius, and remediation proof.", T.green);
    return slide;
  }

  if (n === 6) {
    title(slide, ctx, "Lab Architecture", "Decoupled scanners plus evidence connectors", "Scan jobs run separately. The portal ingests evidence in a standard format.");
    const lanes = [
      ["Student tenant", 80, T.green],
      ["Scanner workers", 350, T.cyan],
      ["Evidence pipeline", 620, T.amber],
      ["Dashboard", 890, T.violet]
    ];
    lanes.forEach(([label, x, accent]) => {
      rect(slide, ctx, x, 205, 220, 330, "#0A1613", T.line);
      text(slide, ctx, label, x + 16, 222, 180, 24, { size: 16, bold: true, color: accent });
    });
    miniCard(slide, ctx, 102, 280, 176, 70, "Cloud accounts", "AWS, GCP, Azure, DO labs", T.green);
    miniCard(slide, ctx, 102, 380, 176, 70, "Local cluster", "Kind or test kubeconfig", T.green);
    miniCard(slide, ctx, 372, 260, 176, 58, "AWS/GCP", "Cloud API checks", T.cyan);
    miniCard(slide, ctx, 372, 335, 176, 58, "Kubernetes", "Pods, RBAC, network policies", T.cyan);
    miniCard(slide, ctx, 372, 410, 176, 58, "IaC", "Full files and repos", T.cyan);
    miniCard(slide, ctx, 642, 260, 176, 58, "Gateway", "Schema validation", T.amber);
    miniCard(slide, ctx, 642, 335, 176, 58, "Queue", "Async decoupling", T.amber);
    miniCard(slide, ctx, 642, 410, 176, 58, "Processor", "Artifact and finding map", T.amber);
    miniCard(slide, ctx, 912, 285, 176, 70, "Findings", "Severity, owner, status", T.violet);
    miniCard(slide, ctx, 912, 390, 176, 70, "Controls", "Evidence and remediation", T.violet);
    line(slide, ctx, 302, 365, 36, 3, T.line);
    line(slide, ctx, 572, 365, 36, 3, T.line);
    line(slide, ctx, 842, 365, 36, 3, T.line);
    return slide;
  }

  if (n === 7) {
    title(slide, ctx, "Agenda", "Two-day workshop flow", "Day 1 builds the attack-path foundation. Day 2 turns it into scanner validation, evidence, and dashboard outcomes.");
    matrix(slide, ctx, 80, 210, ["Time", "Day 1", "Day 2"], [
      ["09:00", "Orientation and multi-cloud mindset", "Kubernetes and live cluster scanning"],
      ["10:30", "Recon to first foothold", "IAM escalation and cloud-native abuse"],
      ["13:15", "Storage and artifact exposure", "Provider-specific kill chains"],
      ["14:45", "SSRF, metadata, and identity", "CI/CD, developer platforms, AI integrations"],
      ["16:00", "Serverless and data tier attacks", "Defenses, evidence, and capstone"]
    ], [135, 485, 485], 58);
    return slide;
  }

  if (n === 8) {
    title(slide, ctx, "Day 1", "From exposure to runtime impact", "The first day shows how small mistakes combine into serious cloud paths.");
    const mods = [
      ["M0", "Setup", "Tenant, portal, dry-run scan"],
      ["M1", "Mindset", "Attack path grammar"],
      ["M2", "Recon", "Owned asset exposure"],
      ["M3", "Storage", "Policies, backups, artifacts"],
      ["M4", "Metadata", "Identity from runtime context"],
      ["M5", "Serverless", "Function, queue, data tier risk"]
    ];
    mods.forEach((m, i) => {
      const x = 88 + (i % 3) * 360;
      const y = 220 + Math.floor(i / 3) * 150;
      miniCard(slide, ctx, x, y, 300, 105, m[0] + " - " + m[1], m[2], [T.green, T.cyan, T.amber, T.violet, T.red, T.green][i]);
    });
    return slide;
  }

  if (n === 9) {
    title(slide, ctx, "Module 2", "Recon to first foothold", "Safe recon inside owned lab assets, then scanner comparison.");
    const flow = [
      ["Inventory", "Cloud assets, DNS, repos"],
      ["Exposure", "Public endpoints and artifacts"],
      ["Validate", "Manual proof and scanner output"],
      ["Prioritize", "Blast radius and owner"],
      ["Record", "Evidence payload and control map"]
    ];
    flow.forEach((f, i) => {
      const x = 86 + i * 215;
      card(slide, ctx, x, 260, 176, 150, f[0], f[1], [T.green, T.cyan, T.amber, T.violet, T.red][i]);
      if (i < flow.length - 1) line(slide, ctx, x + 180, 332, 28, 3, T.line);
    });
    bulletList(slide, ctx, ["Outputs: exposed asset list, screenshot/API evidence, scanner result, remediation owner.", "Key teaching point: an exposed asset is only a finding when impact and evidence are clear."], 96, 480, 970, { size: 18, color: T.green, gap: 52 });
    return slide;
  }

  if (n === 10) {
    title(slide, ctx, "Module 3", "Storage and artifact exposure", "Object storage, backups, logs, and build artifacts are common evidence sources.");
    matrix(slide, ctx, 78, 220, ["Weakness", "Impact", "Evidence", "Fix"], [
      ["Public objects", "Data exposure", "Policy plus object sample", "Block public access"],
      ["Broad principals", "Unintended tenant access", "IAM or ACL snapshot", "Least-privilege policy"],
      ["Build artifacts", "Secret or config leak", "Artifact hash and path", "Sanitize pipeline output"],
      ["Backups/logs", "Historical secret leakage", "Retention and access proof", "Encrypt and restrict"]
    ], [220, 270, 300, 250], 72);
    return slide;
  }

  if (n === 11) {
    title(slide, ctx, "Module 4", "SSRF, metadata, and identity", "The lab focuses on understanding the chain, evidence, and fixes, not public exploitation.");
    const items = [
      ["App weakness", "Request reaches an internal-only metadata surface"],
      ["Metadata", "Short-lived runtime identity details become visible"],
      ["Permissions", "Role or managed identity defines the real blast radius"],
      ["Controls", "IMDS hardening, egress limits, app fix, least privilege"]
    ];
    items.forEach((it, i) => {
      stage(slide, ctx, i + 1, it[0], it[1], 120 + i * 255, 285, 220, [T.green, T.cyan, T.amber, T.red][i]);
      if (i < 3) line(slide, ctx, 120 + i * 255 + 224, 327, 26, 3, T.line);
    });
    card(slide, ctx, 130, 485, 900, 90, "Evidence to capture", "Application route, metadata protection setting, attached identity, effective permissions, scanner output, and remediation ownership across app and cloud teams.", T.green);
    return slide;
  }

  if (n === 12) {
    title(slide, ctx, "Module 5", "Serverless and data tier attacks", "Automation identities, queues, databases, and secrets stores create cloud-native lateral movement.");
    miniCard(slide, ctx, 100, 230, 305, 115, "Function identity", "Excessive permissions attached to a function or job identity.", T.green);
    miniCard(slide, ctx, 465, 230, 305, 115, "Configuration leak", "Environment variables, logs, and build-time secrets.", T.amber);
    miniCard(slide, ctx, 830, 230, 305, 115, "Managed data", "Database, queue, or object store reachable beyond intended boundary.", T.cyan);
    miniCard(slide, ctx, 220, 420, 305, 115, "Scanner proof", "Role policy, network exposure, secret class, and resource lineage.", T.violet);
    miniCard(slide, ctx, 705, 420, 305, 115, "Remediation", "Reduce permissions, rotate secrets, restrict network, add detection.", T.red);
    line(slide, ctx, 408, 286, 52, 3, T.line);
    line(slide, ctx, 774, 286, 52, 3, T.line);
    line(slide, ctx, 518, 475, 180, 3, T.line);
    return slide;
  }

  if (n === 13) {
    title(slide, ctx, "Module 6", "Containers and Kubernetes", "Live cluster scanning through kubeconfig plus IaC drift comparison.");
    const cols = [
      ["Workloads", "Privileged pods, host mounts, default namespace usage"],
      ["Identity", "Service accounts, cluster roles, role bindings"],
      ["Network", "Exposed services and missing network policies"],
      ["Secrets", "Mounted secrets and broad namespace visibility"],
      ["Drift", "Live cluster state versus YAML or Terraform intent"]
    ];
    cols.forEach((c, i) => miniCard(slide, ctx, 78 + (i % 3) * 360, 220 + Math.floor(i / 3) * 155, 300, 112, c[0], c[1], [T.green, T.cyan, T.amber, T.violet, T.red][i]));
    card(slide, ctx, 78, 540, 1040, 78, "Scanner requirement", "With credentials or kubeconfig: query pods, services, namespaces, RBAC, network policies, and compare running infrastructure against IaC files.", T.green);
    return slide;
  }

  if (n === 14) {
    title(slide, ctx, "Day 2", "From scanner validation to executive proof", "The second day standardizes findings across providers and turns them into controls.");
    const mods = [
      ["M6", "Kubernetes", "Live state, RBAC, policy, drift"],
      ["M7", "IAM abuse", "Identity graph and escalation edges"],
      ["M8", "Provider chains", "AWS, Azure, GCP, DO equivalents"],
      ["M9", "CI/CD and AI", "Automation identities and guardrails"],
      ["M10", "Defenses", "Prevention, detection, evidence"],
      ["Capstone", "Briefing", "Attack path plus remediation proof"]
    ];
    mods.forEach((m, i) => {
      const x = 88 + (i % 3) * 360;
      const y = 220 + Math.floor(i / 3) * 150;
      miniCard(slide, ctx, x, y, 300, 105, m[0] + " - " + m[1], m[2], [T.green, T.cyan, T.amber, T.violet, T.red, T.green][i]);
    });
    return slide;
  }

  if (n === 15) {
    title(slide, ctx, "Module 7", "IAM escalation graph", "Participants learn to see permissions as graph edges, then validate high-risk edges with scanner evidence.");
    const nodes = [
      ["User or CI token", 110, 300, T.green],
      ["Assumable role", 360, 220, T.cyan],
      ["Service account", 360, 385, T.amber],
      ["Admin-like action", 650, 300, T.red],
      ["Sensitive data", 930, 300, T.violet]
    ];
    nodes.forEach(([label, x, y, accent]) => {
      rect(slide, ctx, x, y, 185, 72, T.panel, accent);
      text(slide, ctx, label, x + 14, y + 24, 157, 20, { size: 15, bold: true, color: accent, align: "center" });
    });
    line(slide, ctx, 298, 333, 58, 3, T.line);
    line(slide, ctx, 548, 253, 95, 3, T.line);
    line(slide, ctx, 548, 418, 95, 3, T.line);
    line(slide, ctx, 838, 333, 82, 3, T.line);
    text(slide, ctx, "Graph edges are where remediation starts: trust policy, action, condition, resource scope, and exception reason.", 130, 520, 920, 48, { size: 21, bold: true, color: T.ink, align: "center" });
    return slide;
  }

  if (n === 16) {
    title(slide, ctx, "Module 8", "Provider-specific equivalence", "Different clouds, same core evidence questions: identity, exposure, data, runtime, logs.");
    providerBand(slide, ctx, "AWS", "IAM role, S3 policy, Lambda role, EC2 metadata, EKS RBAC", 90, 215, 1000, T.amber);
    providerBand(slide, ctx, "Azure", "Entra ID, managed identity, storage account, Functions, AKS", 90, 300, 1000, T.cyan);
    providerBand(slide, ctx, "GCP", "Project IAM, service account, Cloud Storage, Functions, GKE", 90, 385, 1000, T.green);
    providerBand(slide, ctx, "DO", "Projects, Spaces, Droplets, registries, managed DB, DOKS", 90, 470, 1000, T.violet);
    text(slide, ctx, "Normalize the evidence, not the provider terminology.", 90, 575, 840, 32, { size: 24, bold: true, color: T.green });
    return slide;
  }

  if (n === 17) {
    title(slide, ctx, "Module 9", "CI/CD and developer platforms", "Deployment platforms are cloud-adjacent control planes with secrets, identities, and build artifacts.");
    const p = [
      ["Repo", "Workflow file and secrets"],
      ["CI runner", "Build logs and tokens"],
      ["Deploy platform", "Project token and env vars"],
      ["Cloud account", "OIDC trust and runtime role"],
      ["Evidence", "Connector payload to dashboard"]
    ];
    p.forEach((f, i) => {
      card(slide, ctx, 82 + i * 218, 260, 180, 150, f[0], f[1], [T.green, T.cyan, T.amber, T.violet, T.red][i]);
      if (i < p.length - 1) line(slide, ctx, 264 + i * 218, 332, 30, 3, T.line);
    });
    bulletList(slide, ctx, ["Key checks: secret scope, OIDC audience, build artifact exposure, deployment token privileges, branch protections.", "Evidence connector: source_system=ci_cd, asset_type=pipeline, provider=github_or_platform."], 95, 480, 980, { size: 17, color: T.green, gap: 50 });
    return slide;
  }

  if (n === 18) {
    title(slide, ctx, "Module 9", "AI integrations and over-privileged automation", "AI-assisted workflows are useful, but they must be contained like any other automation identity.");
    card(slide, ctx, 90, 220, 300, 250, "Risk pattern", "Agent or model-serving workflow receives broad cloud credentials, reads sensitive context, or can trigger scanner actions without approvals.", T.red);
    card(slide, ctx, 465, 220, 300, 250, "Containment", "Host private models on controlled VMs when needed, isolate scanner permissions, log prompts and actions, and enforce approval gates.", T.green);
    card(slide, ctx, 840, 220, 300, 250, "Cost model", "Prefer small models for summarization, batch findings, cache recommendations, and reserve heavier models for capstone-quality explanations.", T.amber);
    matrix(slide, ctx, 160, 520, ["Control", "Workshop evidence"], [
      ["Permission boundary", "Role policy and denied action sample"],
      ["Action logging", "Audit event linked to scan_job_id"],
      ["Data minimization", "Redacted prompt and artifact hash"]
    ], [300, 620], 36);
    return slide;
  }

  if (n === 19) {
    title(slide, ctx, "Module 10", "Defenses that actually work", "Every finding should map to prevention, detection, evidence, and owner.");
    const stack = [
      ["Prevent", "Least privilege, private endpoints, policy-as-code, protected branches"],
      ["Detect", "Cloud logs, scanner cadence, drift checks, anomaly alerts"],
      ["Respond", "Owner, severity, due date, ticket, rollback or rotation"],
      ["Prove", "Evidence artifact, scan result, control mapping, remediation proof"]
    ];
    stack.forEach((s, i) => {
      rect(slide, ctx, 170 + i * 205, 255 - i * 18, 180, 260 + i * 18, [T.panel, "#102A23", "#12362D", "#154235"][i], [T.green, T.cyan, T.amber, T.violet][i]);
      text(slide, ctx, s[0], 190 + i * 205, 285 - i * 18, 140, 28, { size: 20, bold: true, color: [T.green, T.cyan, T.amber, T.violet][i], align: "center" });
      text(slide, ctx, s[1], 190 + i * 205, 340 - i * 18, 140, 130, { size: 13, color: T.ink, align: "center" });
    });
    return slide;
  }

  if (n === 20) {
    title(slide, ctx, "CloudGuard Integration", "Evidence connector loop", "This is the project architecture your boss asked for: portal decoupled from scan jobs, with connectors feeding normalized evidence.");
    const loop = [
      ["1. Scan job", "Worker runs independently"],
      ["2. Connector", "Normalizes evidence schema"],
      ["3. Gateway", "Validates tenant_id and payload"],
      ["4. Processor", "Stores artifact and maps controls"],
      ["5. Dashboard", "Shows risk, owner, remediation"]
    ];
    loop.forEach((l, i) => {
      const x = 86 + i * 216;
      stage(slide, ctx, i + 1, l[0], l[1], x, 280, 178, [T.green, T.cyan, T.amber, T.violet, T.red][i]);
      if (i < loop.length - 1) line(slide, ctx, x + 182, 322, 26, 3, T.line);
    });
    card(slide, ctx, 130, 500, 910, 80, "Contract", "Every scanner must send tenant_id, scanner_type, scan_job_id, asset_id, finding_id, severity, control_ids, evidence_type, evidence_uri, observed_at, status, and remediation.", T.green);
    return slide;
  }

  if (n === 21) {
    title(slide, ctx, "Capstone", "End-to-end investigation and briefing", "Teams must find the most important path, prove it, and explain how to fix it.");
    matrix(slide, ctx, 90, 220, ["Area", "Points", "What good looks like"], [
      ["Attack path", "20", "Correct chain from exposure to impact"],
      ["Evidence", "20", "Clean artifacts with tenant_id and lineage"],
      ["Scanner validation", "20", "Manual proof matches scanner findings"],
      ["Control mapping", "15", "Findings linked to controls and owners"],
      ["Remediation", "15", "Practical fix with proof requirement"],
      ["Briefing", "10", "Leadership-ready risk story"]
    ], [220, 120, 720], 48);
    return slide;
  }

  if (n === 22) {
    title(slide, ctx, "Instructor Prep", "What must exist before workshop day", "The quality of the lab depends on predictable setup, reset, budgets, and evidence fixtures.");
    bulletList(slide, ctx, [
      "Disposable cloud accounts/projects with budgets and region restrictions.",
      "Terraform and Kubernetes lab modules with reset and teardown scripts.",
      "Scanner worker compose files and sample credentials by tenant.",
      "Evidence schema examples and negative test cases.",
      "Capstone flags, scoring sheet, solution guide, and cleanup checklist.",
      "Known-good dashboard tenant with sample data for demo fallback."
    ], 110, 220, 950, { size: 20, gap: 56, color: T.green });
    return slide;
  }

  if (n === 23) {
    title(slide, ctx, "Student Pack", "What every participant receives", "The handout makes the workshop reusable after the event.");
    const packs = [
      ["Lab guide", "Step-by-step authorized exercises with expected evidence outputs."],
      ["Cheat sheets", "Cloud CLI, kubectl, Terraform, evidence schema, severity guide."],
      ["Hardening list", "Provider-specific controls mapped to scanner findings."],
      ["Connector examples", "AWS, GCP, Kubernetes, IaC, CI/CD payload templates."],
      ["Cleanup", "Credential rotation, resource teardown, cost check, audit log export."],
      ["Backlog", "Scanner improvements and dashboard work items after the workshop."]
    ];
    packs.forEach((p, i) => miniCard(slide, ctx, 88 + (i % 3) * 360, 220 + Math.floor(i / 3) * 150, 300, 105, p[0], p[1], [T.green, T.cyan, T.amber, T.violet, T.red, T.green][i]));
    return slide;
  }

  if (n === 24) {
    title(slide, ctx, "Rollout", "How to make this workshop real", "Start small, validate the labs, then expand providers and capstone depth.");
    const steps = [
      ["Week 1", "Finalize syllabus, evidence schema, and lab account boundaries."],
      ["Week 2", "Build vulnerable AWS, GCP, Kubernetes, and IaC fixtures."],
      ["Week 3", "Run internal dry run with scanner workers and dashboard ingestion."],
      ["Week 4", "Deliver workshop, collect feedback, create scanner backlog."]
    ];
    steps.forEach((s, i) => stage(slide, ctx, i + 1, s[0], s[1], 116 + i * 260, 275, 220, [T.green, T.cyan, T.amber, T.violet][i]));
    card(slide, ctx, 155, 505, 860, 86, "Final message", "The workshop should prove the architecture as much as it teaches cloud security: decoupled scanners, tenant-safe evidence, and a dashboard that turns technical findings into accountable remediation.", T.green);
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
  await fs.mkdir(qaDir, { recursive: true });
  await fs.writeFile(path.join(slidesDir, "deck-utils.mjs"), sharedModule, "utf8");

  for (let i = 1; i <= slideCount; i += 1) {
    const padded = String(i).padStart(2, "0");
    const module = [
      'import { buildSlide } from "./deck-utils.mjs";',
      "",
      `export async function slide${padded}(presentation, ctx) {`,
      `  return buildSlide(presentation, ctx, ${i});`,
      "}",
      ""
    ].join("\n");
    await fs.writeFile(path.join(slidesDir, `slide-${padded}.mjs`), module, "utf8");
  }

  await fs.writeFile(
    path.join(qaDir, "comeback-scorecard.txt"),
    [
      "Structured visuals use editable artifact-tool shapes and text.",
      "No native chart was needed; matrices and flow diagrams are built from editable shapes.",
      "No whole-slide image backgrounds are used.",
      "Deck is generated from slide modules and exported to PPTX."
    ].join("\n") + "\n",
    "utf8"
  );

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

  console.log(result.stdout);
  console.log(JSON.stringify({
    finalPptx,
    workspace,
    previewDir,
    contactSheet: path.join(previewDir, "contact-sheet.png")
  }, null, 2));
}

main().catch((error) => {
  console.error(error.stack || error.message || String(error));
  process.exit(1);
});
