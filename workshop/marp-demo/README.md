# DeepTrustxAI Marp Workshop Decks

This folder contains the DeepTrustxAI-branded cloud security workshop, a reusable logo-enabled Marp template, and the earlier CloudGuard project demo deck.

The Cloud Security workshop is now organized in the corrected four-module flow: CCSP and cloud vulnerability concepts first, vulnerable app/deployment second, CloudGuard scanner usage third, and open-source tool usage fourth. The Kubernetes track remains a separate two-day track.

## Files

- `deeptrustxai-cloud-security-2-day-workshop.md` - 40-slide participant-facing Cloud Security workshop deck
- `deeptrustxai-cloud-security-module-wise-syllabus.md` - 26-slide module-wise review deck for the boss/sponsor discussion
- `deeptrustxai-kubernetes-security-2-day-workshop.md` - 44-slide Kubernetes Security track
- `../deeptrustxai-four-day-cloud-kubernetes-training-modules.md` - complete four-day module guide with CISSP/CCSP mapping
- `deeptrustxai-cloud-attack-workshop.md` - canonical 48-slide Marp training deck
- `deeptrustxai-marp-template.md` - reusable DeepTrustxAI presentation starter with logo already inserted
- `themes/deeptrustxai.css` - DeepTrustxAI workshop theme
- `images/deeptrustxai-logo.png` - official logo asset from `deeptrustxai.com`
- `../deeptrustxai-cloud-security-workshop-modules.md` - instructor module guide
- `cloudguard-workshop-demo.md` - editable Marp slide source with CloudGuard project data
- `themes/cloudguard.css` - custom CloudGuard theme
- `images/grc-evidence-flow.png` - sample architecture image used inside the deck
- `images/setup-dokploy-cloudguard-stack.png` - Dokploy PoC setup image
- `exports/` - generated HTML/PDF/PPTX output
- `github-pages-workflow.yml` - example GitHub Actions workflow for publishing the deck

## Local Preview

Install/run Marp through `npx`:

```bash
npx --yes @marp-team/marp-cli \
  workshop/marp-demo/deeptrustxai-cloud-security-2-day-workshop.md \
  --theme workshop/marp-demo/themes/deeptrustxai.css \
  --html \
  --allow-local-files \
  --output workshop/marp-demo/exports/deeptrustxai-cloud-security-2-day-workshop.html
```

Open:

```text
workshop/marp-demo/exports/deeptrustxai-cloud-security-2-day-workshop.html
```

## Export PDF And PPTX

```bash
npx --yes @marp-team/marp-cli \
  workshop/marp-demo/deeptrustxai-cloud-security-2-day-workshop.md \
  --theme workshop/marp-demo/themes/deeptrustxai.css \
  --pdf \
  --allow-local-files \
  --output workshop/marp-demo/exports/deeptrustxai-cloud-security-2-day-workshop.pdf
```

Replace `cloud-security` with `kubernetes-security` in the source and output filenames to build the Kubernetes track.

The checked workshop PPTX is generated as an editable PowerPoint mirror from the same Marp content. Use the Marp HTML/PDF for pixel-consistent delivery and the PPTX when instructors need to make last-minute PowerPoint edits.

## Reuse The Branded Template

Duplicate `deeptrustxai-marp-template.md`, change the title and slide content, and keep these frontmatter values:

```yaml
theme: deeptrustxai
header: '![DeepTrustxAI](images/deeptrustxai-logo.png) **DeepTrustxAI**'
footer: 'DeepTrustxAI | Cybersecurity Training'
```

The logo appears on ordinary slides through the header. Cover, module-divider, and closing slides include a larger brand lockup.

## GitHub Workflow Idea

For the real workshop, we can add a GitHub Action that:

1. Runs on every push to `main`.
2. Builds the Marp Markdown into HTML, PDF, and PPTX.
3. Publishes the HTML deck to GitHub Pages.
4. Uploads PDF/PPTX as workflow artifacts.

This lets the team update slides through GitHub while travelling or during workshop preparation.

The file `github-pages-workflow.yml` is a ready reference. In a real repository,
copy it to `.github/workflows/marp-pages.yml`, enable GitHub Pages, and push to
`main`.
