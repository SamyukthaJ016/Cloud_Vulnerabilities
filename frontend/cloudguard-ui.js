(function () {
    const originalFetch = window.fetch.bind(window);
    const OIDC_STATE_KEY = "cloudguard.oidc.state";
    const OIDC_VERIFIER_KEY = "cloudguard.oidc.verifier";
    const OIDC_TOKENS_KEY = "cloudguard.oidc.tokens";

    function isSameOrigin(input) {
        const rawUrl = input instanceof Request ? input.url : String(input);
        return new URL(rawUrl, window.location.origin).origin === window.location.origin;
    }

    function base64Url(bytes) {
        let binary = "";
        for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
        return window.btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }

    function randomUrlSafeValue() {
        const bytes = new Uint8Array(32);
        window.crypto.getRandomValues(bytes);
        return base64Url(bytes);
    }

    async function pkceChallenge(verifier) {
        const digest = await window.crypto.subtle.digest(
            "SHA-256",
            new TextEncoder().encode(verifier),
        );
        return base64Url(digest);
    }

    function oidcEndpoint(keycloakUrl, realm, endpoint) {
        const base = keycloakUrl.toString().replace(/\/$/, "");
        return `${base}/realms/${encodeURIComponent(realm)}/protocol/openid-connect/${endpoint}`;
    }

    function readStoredTokens() {
        try {
            return JSON.parse(window.sessionStorage.getItem(OIDC_TOKENS_KEY) || "null");
        } catch (_error) {
            return null;
        }
    }

    function storeTokens(response, previousRefreshToken = null) {
        const tokens = {
            accessToken: response.access_token,
            refreshToken: response.refresh_token || previousRefreshToken,
            expiresAt: Date.now() + (Number(response.expires_in) || 300) * 1000,
        };
        window.sessionStorage.setItem(OIDC_TOKENS_KEY, JSON.stringify(tokens));
        return tokens;
    }

    function clearOidcCallback() {
        const url = new URL(window.location.href);
        ["code", "state", "session_state", "iss", "error", "error_description"].forEach((key) => {
            url.searchParams.delete(key);
        });
        window.history.replaceState(window.history.state, "", url.toString());
    }

    async function beginAuthorization(config, keycloakUrl, redirectUri) {
        const state = randomUrlSafeValue();
        const verifier = randomUrlSafeValue();
        window.sessionStorage.setItem(OIDC_STATE_KEY, state);
        window.sessionStorage.setItem(OIDC_VERIFIER_KEY, verifier);

        const authorizationUrl = new URL(oidcEndpoint(keycloakUrl, config.realm, "auth"));
        authorizationUrl.search = new URLSearchParams({
            client_id: config.client_id,
            redirect_uri: redirectUri,
            response_type: "code",
            response_mode: "query",
            scope: "openid profile email",
            state,
            code_challenge: await pkceChallenge(verifier),
            code_challenge_method: "S256",
        }).toString();
        window.location.assign(authorizationUrl.toString());
        return new Promise(() => {});
    }

    async function requestTokens(keycloakUrl, realm, parameters) {
        const response = await originalFetch(oidcEndpoint(keycloakUrl, realm, "token"), {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams(parameters),
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok || !payload.access_token) {
            throw new Error(payload.error_description || payload.error || "Keycloak token exchange failed");
        }
        return payload;
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

        const redirectUri = `${window.location.origin}${window.location.pathname}`;
        const callback = new URL(window.location.href).searchParams;
        let tokens = readStoredTokens();

        if (callback.has("error")) {
            const message = callback.get("error_description") || callback.get("error");
            clearOidcCallback();
            throw new Error(`Keycloak authorization failed: ${message}`);
        }

        if (callback.has("code") && callback.has("state")) {
            const expectedState = window.sessionStorage.getItem(OIDC_STATE_KEY);
            const verifier = window.sessionStorage.getItem(OIDC_VERIFIER_KEY);
            if (callback.get("state") !== expectedState || !verifier) {
                clearOidcCallback();
                window.sessionStorage.removeItem(OIDC_TOKENS_KEY);
                return beginAuthorization(config, keycloakUrl, redirectUri);
            }

            const response = await requestTokens(keycloakUrl, config.realm, {
                grant_type: "authorization_code",
                client_id: config.client_id,
                code: callback.get("code"),
                redirect_uri: redirectUri,
                code_verifier: verifier,
            });
            tokens = storeTokens(response);
            window.sessionStorage.removeItem(OIDC_STATE_KEY);
            window.sessionStorage.removeItem(OIDC_VERIFIER_KEY);
            clearOidcCallback();
        }

        if (!tokens?.accessToken) {
            return beginAuthorization(config, keycloakUrl, redirectUri);
        }

        const auth = {
            token: tokens.accessToken,
            async updateToken(minValidity = 30) {
                if (tokens.expiresAt - Date.now() > minValidity * 1000) return false;
                if (!tokens.refreshToken) {
                    window.sessionStorage.removeItem(OIDC_TOKENS_KEY);
                    return beginAuthorization(config, keycloakUrl, redirectUri);
                }
                try {
                    const response = await requestTokens(keycloakUrl, config.realm, {
                        grant_type: "refresh_token",
                        client_id: config.client_id,
                        refresh_token: tokens.refreshToken,
                    });
                    tokens = storeTokens(response, tokens.refreshToken);
                    auth.token = tokens.accessToken;
                    return true;
                } catch (error) {
                    window.sessionStorage.removeItem(OIDC_TOKENS_KEY);
                    return beginAuthorization(config, keycloakUrl, redirectUri);
                }
            },
        };
        await auth.updateToken(30);
        return auth;
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
