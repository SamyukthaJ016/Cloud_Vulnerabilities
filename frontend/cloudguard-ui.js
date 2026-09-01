(function () {
    const originalFetch = window.fetch.bind(window);
    let keycloak = null;

    function isSameOrigin(input) {
        const rawUrl = input instanceof Request ? input.url : String(input);
        return new URL(rawUrl, window.location.origin).origin === window.location.origin;
    }

    async function loadKeycloakAdapter() {
        if (window.Keycloak) return;

        const adapter = await import("/keycloak.js");
        if (typeof adapter.default !== "function") {
            throw new Error("Unable to load the Keycloak adapter");
        }
        window.Keycloak = adapter.default;
    }

    async function initialiseAuthentication() {
        const response = await originalFetch("/api/auth/config", { credentials: "same-origin" });
        if (!response.ok) throw new Error("Unable to load CloudGuard authentication configuration");
        const config = await response.json();
        if (!config.enabled) return null;
        if (!config.url || !config.realm || !config.client_id) {
            throw new Error("CloudGuard Keycloak configuration is incomplete");
        }

        const keycloakUrl = new URL(config.url, window.location.origin);
        const localKeycloak = keycloakUrl.protocol === "http:" &&
            ["localhost", "127.0.0.1"].includes(keycloakUrl.hostname);
        if (keycloakUrl.protocol !== "https:" && !localKeycloak) {
            throw new Error("CloudGuard requires HTTPS for Keycloak authentication");
        }

        await loadKeycloakAdapter();
        keycloak = new window.Keycloak({
            url: keycloakUrl.toString().replace(/\/$/, ""),
            realm: config.realm,
            clientId: config.client_id,
        });
        await keycloak.init({
            onLoad: "login-required",
            checkLoginIframe: false,
            pkceMethod: "S256",
            redirectUri: window.location.href,
        });
        return keycloak;
    }

    const authenticationReady = initialiseAuthentication().catch((error) => {
        console.error("CloudGuard authentication could not be initialized:", error);
        document.documentElement.dataset.authError = "true";
        throw error;
    });

    window.fetch = async function (input, init) {
        const auth = await authenticationReady;
        if (!auth || !isSameOrigin(input)) {
            return originalFetch(input, init);
        }

        await auth.updateToken(30);
        const headers = new Headers(
            init && init.headers ? init.headers : (input instanceof Request ? input.headers : undefined)
        );
        if (auth.token && !headers.has("Authorization")) {
            headers.set("Authorization", `Bearer ${auth.token}`);
        }
        return originalFetch(input, { ...init, headers });
    };

    function detectPage() {
        const path = window.location.pathname;
        const title = document.title.toLowerCase();
        if (path.includes("scheduled") || path.includes("schedules")) return "schedules";
        if (path.includes("history")) return "history";
        if (path.includes("operations")) return "operations";
        if (path.includes("compliance")) return "compliance";
        if (path.includes("reason-act") || path.includes("reason_act")) return "reason";
        if (path.includes("grc")) return "grc";
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
                reason: "/reason_act.html",
                grc: "/grc.html"
            };
        }
        return {
            home: "/",
            dashboard: "/dashboard",
            schedules: "/scheduled_scans",
            history: "/history",
            operations: "/operations",
            compliance: "/compliance",
            reason: "/reason-act",
            grc: "/grc"
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
            ["reason", "Reason & Act"],
            ["grc", "GRC"]
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
