(function () {
    function detectPage() {
        const path = window.location.pathname;
        const title = document.title.toLowerCase();
        if (path.includes("scheduled") || path.includes("schedules")) return "schedules";
        if (path.includes("history")) return "history";
        if (path.includes("operations")) return "operations";
        if (path.includes("compliance")) return "compliance";
        if (path.includes("reason-act") || path.includes("reason_act")) return "reason";
        if (path.includes("dashboard") || title.includes("dashboard")) return "dashboard";
        return "home";
    }

    function routeMap() {
        const staticMode = window.location.pathname.endsWith(".html");
        if (staticMode) {
            return {
                home: "/index.html",
                dashboard: "/dashboard.html",
                schedules: "/scheduled_scans.html",
                history: "/history.html",
                operations: "/operations.html",
                compliance: "/compliance.html",
                reason: "/reason_act.html"
            };
        }
        return {
            home: "/",
            dashboard: "/dashboard",
            schedules: "/scheduled_scans",
            history: "/history",
            operations: "/operations",
            compliance: "/compliance",
            reason: "/reason-act"
        };
    }

    function addShell() {
        if (!document.body || document.querySelector(".cg-shell")) return;

        const page = detectPage();
        const routes = routeMap();
        document.body.classList.add("cg-enhanced", "cg-" + page);

        const nav = [
            ["home", "Scan"],
            ["dashboard", "Dashboard"],
            ["schedules", "Schedules"],
            ["history", "History"],
            ["operations", "Operations"],
            ["compliance", "Compliance"],
            ["reason", "Reason & Act"]
        ];

        const shell = document.createElement("div");
        shell.className = "cg-shell";
        shell.innerHTML = `
            <div class="cg-shell-inner">
                <a class="cg-brand" href="${routes.home}" aria-label="CloudGuard scan home">
                    <span class="cg-mark">CG</span>
                    <span class="cg-brand-copy">
                        <span class="cg-brand-name">CloudGuard</span>
                        <span class="cg-brand-subtitle">Multi-cloud security console</span>
                    </span>
                </a>
                <nav class="cg-nav" aria-label="Primary navigation">
                    ${nav.map(([key, label]) => `
                        <a class="cg-nav-link ${page === key ? "active" : ""}" href="${routes[key]}">${label}</a>
                    `).join("")}
                </nav>
                <div class="cg-actions">
                    <a class="cg-primary-link" href="${routes.home}">New scan</a>
                </div>
            </div>
        `;
        document.body.prepend(shell);
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", addShell);
    } else {
        addShell();
    }
})();
