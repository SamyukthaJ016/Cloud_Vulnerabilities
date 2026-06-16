# CloudGuard Marp Project Deck

This is a small project deck showing how CloudGuard workshop or status slides can be maintained in GitHub using Marp.

The deck now contains actual CloudGuard project content: scanner coverage, evidence connector flow, queue-based scan jobs, GRC evidence mapping, Kubernetes/IaC scanner scope, deployment PoC, and the multi-tenant direction.

## Files

- `cloudguard-workshop-demo.md` - editable Marp slide source with CloudGuard project data
- `themes/cloudguard.css` - custom CloudGuard theme
- `images/grc-evidence-flow.png` - sample architecture image used inside the deck
- `images/setup-dokploy-cloudguard-stack.png` - Dokploy PoC setup image
- `exports/` - generated HTML/PDF/PPTX output
- `github-pages-workflow.yml` - example GitHub Actions workflow for publishing the deck

## Local Preview

Install/run Marp through `npx`:

```bash
npx --yes @marp-team/marp-cli workshop/marp-demo/cloudguard-workshop-demo.md --theme workshop/marp-demo/themes/cloudguard.css --html --allow-local-files --output workshop/marp-demo/exports/cloudguard-workshop-demo.html
```

Open:

```text
workshop/marp-demo/exports/cloudguard-workshop-demo.html
```

## Export PDF And PPTX

```bash
npx --yes @marp-team/marp-cli workshop/marp-demo/cloudguard-workshop-demo.md --theme workshop/marp-demo/themes/cloudguard.css --pdf --allow-local-files --output workshop/marp-demo/exports/cloudguard-workshop-demo.pdf
npx --yes @marp-team/marp-cli workshop/marp-demo/cloudguard-workshop-demo.md --theme workshop/marp-demo/themes/cloudguard.css --pptx --allow-local-files --output workshop/marp-demo/exports/cloudguard-workshop-demo.pptx
```

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
