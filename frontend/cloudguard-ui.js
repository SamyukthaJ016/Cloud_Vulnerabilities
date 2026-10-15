/* CloudGuard scan meters: derived only from one pinned, completed scan. */
(function () {
    function model(summary, findings) {
        if (!summary || !Array.isArray(findings) || !Number.isInteger(summary.total_resources) || summary.total_resources < 0 || !Number.isInteger(summary.total_findings) || summary.total_findings !== findings.length || !Number.isInteger(summary.public_resources) || summary.public_resources < 0 || summary.public_resources > summary.total_resources) throw new Error('Incomplete scan snapshot');
        const resources = summary.total_resources;
        const total = findings.length;
        const priority = findings.filter(f => ['CRITICAL', 'HIGH'].includes(String(f.severity || '').toUpperCase())).length;
        const measured = resources > 0;
        return [
            { title: 'Scan posture estimate', value: measured && Number.isFinite(summary.security_score) ? Math.round(Math.max(0, Math.min(100, summary.security_score))) : null, detail: `${resources} resources · ${total} findings`, direction: 'Higher is better', tone: 'mint' },
            { title: 'Critical & high findings', value: measured ? (total ? Math.round(priority / total * 100) : 0) : null, detail: `${priority} of ${total} findings need priority review`, direction: 'Lower is better', tone: priority ? 'amber' : 'mint' },
            { title: 'Public resource exposure', value: measured ? Math.round(summary.public_resources / resources * 100) : null, detail: `${summary.public_resources} of ${resources} resources flagged public`, direction: 'Lower is better', tone: summary.public_resources ? 'amber' : 'lime' },
        ];
    }

    async function latestSnapshot(request = window.fetch) {
        const scopeRes = await request('/api/dashboard-scope');
        const scope = await scopeRes.json();
        if (!scopeRes.ok || scope.status !== 'success' || !Array.isArray(scope.scan_ids) || scope.scan_ids.length > 1 || scope.scan_ids.some(id => !Number.isInteger(id) || id < 1)) throw new Error('Could not load the latest scan');
        if (!scope.scan_ids.length) return null;
        const filter = `?scan_ids=${scope.scan_ids[0]}`;
        const summaryRes = await request(`/posture/dashboard${filter}`);
        const summary = await summaryRes.json();
        if (!summaryRes.ok) throw new Error('Could not load the scan summary');
        const findings = [];
        let more = true;
        while (more) {
            const response = await request(`/api/latest-findings${filter}&limit=200&offset=${findings.length}`);
            const page = await response.json();
            if (!response.ok || page.status !== 'success' || !Array.isArray(page.data) || (page.has_more && !page.data.length)) throw new Error('Could not load complete scan findings');
            findings.push(...page.data);
            more = page.has_more === true;
        }
        model(summary, findings); // Reject partial or inconsistent responses.
        return { summary, findings, scanId: scope.scan_ids[0] };
    }

    function mount(anchor) {
        if (!anchor || document.getElementById('cg-scan-meters')) return;
        const section = document.createElement('section');
        section.id = 'cg-scan-meters';
        section.className = 'cg-meter-panel';
        section.setAttribute('aria-label', 'Latest scan security meters');
        section.innerHTML = `<div class="cg-meter-heading"><div><p class="cg-eyebrow">SCAN INTELLIGENCE</p><h2>Latest scan, at a glance</h2><p id="cg-meter-scope" class="cg-meter-scope">Loading the completed scan…</p></div><a class="cg-text-link" href="${window.location.pathname.endsWith('.html') ? '/dashboard.html' : '/dashboard'}">Explore findings ↗</a></div><div class="cg-meter-grid">${[0, 1, 2].map(() => `<article class="cg-meter-card"><h3></h3><div class="cg-gauge"><svg viewBox="0 0 200 176" aria-hidden="true"><circle cx="100" cy="100" r="70" fill="none" stroke="#263b2d" stroke-width="11" stroke-linecap="round" stroke-dasharray="329.87 439.82" transform="rotate(135 100 100)"/><circle class="cg-gauge-arc" cx="100" cy="100" r="70" fill="none" stroke-width="11" stroke-linecap="round" stroke-dasharray="0 439.82" transform="rotate(135 100 100)"/><text x="100" y="104" text-anchor="middle" class="cg-gauge-value">—</text><text x="100" y="126" text-anchor="middle" class="cg-gauge-direction">LOADING</text></svg></div><p class="cg-meter-detail">Checking scan data…</p></article>`).join('')}</div><p class="cg-meter-note">Posture estimate = 100 − (findings ÷ resources × 100), with a minimum of 0. Scanner output requires review; it is not a compliance assessment.</p>`;
        anchor.before(section);
        state('loading');
    }

    function state(status) {
        const root = document.getElementById('cg-scan-meters');
        if (!root) return;
        root.setAttribute('aria-busy', status === 'loading' ? 'true' : 'false');
        const titles = ['Scan posture estimate', 'Critical & high findings', 'Public resource exposure'];
        root.querySelectorAll('.cg-meter-card').forEach((card, index) => {
            card.querySelector('h3').textContent = titles[index];
            const gauge = card.querySelector('.cg-gauge');
            ['role', 'aria-label', 'aria-valuenow', 'aria-valuemin', 'aria-valuemax', 'aria-valuetext'].forEach(name => gauge.removeAttribute(name));
            card.querySelector('.cg-gauge-value').textContent = status === 'loading' ? '—' : status === 'empty' ? 'No data' : 'Unavailable';
            card.querySelector('.cg-gauge-direction').textContent = status === 'loading' ? 'LOADING' : status === 'empty' ? 'AWAITING SCAN' : 'TRY AGAIN';
            card.querySelector('.cg-gauge-arc').setAttribute('stroke-dasharray', '0 439.82');
            card.querySelector('.cg-gauge-arc').style.opacity = '0';
            card.querySelector('.cg-meter-detail').textContent = status === 'empty' ? 'Run a scan to establish your baseline.' : status === 'loading' ? 'Checking scan data…' : 'Scan data could not be loaded.';
        });
        document.getElementById('cg-meter-scope').textContent = status === 'empty' ? 'No completed scan is available.' : status === 'loading' ? 'Loading the completed scan…' : 'Data unavailable. Open the dashboard to retry.';
    }

    function update(summary, findings, scope) {
        const root = document.getElementById('cg-scan-meters');
        if (!root) return;
        const values = model(summary, findings);
        if (!summary.total_resources) { state('empty'); return; }
        root.setAttribute('aria-busy', 'false');
        document.getElementById('cg-meter-scope').textContent = scope;
        root.querySelectorAll('.cg-meter-card').forEach((card, index) => {
            const meter = values[index];
            card.querySelector('h3').textContent = meter.title;
            card.querySelector('.cg-gauge-value').textContent = meter.value === null ? 'No data' : `${meter.value}%`;
            card.querySelector('.cg-gauge-direction').textContent = meter.direction.toUpperCase();
            card.querySelector('.cg-meter-detail').textContent = meter.detail;
            const gauge = card.querySelector('.cg-gauge');
            if (meter.value !== null) {
                gauge.setAttribute('role', 'meter');
                gauge.setAttribute('aria-label', meter.title);
                gauge.setAttribute('aria-valuemin', '0'); gauge.setAttribute('aria-valuemax', '100');
                gauge.setAttribute('aria-valuenow', String(meter.value));
                gauge.setAttribute('aria-valuetext', `${meter.value}%. ${meter.detail}. ${meter.direction}.`);
            }
            const arc = card.querySelector('.cg-gauge-arc');
            arc.setAttribute('stroke', meter.tone === 'amber' ? '#fbbf24' : meter.tone === 'lime' ? '#a3e635' : '#6ee7b7');
            arc.setAttribute('stroke-dasharray', `${329.87 * (meter.value || 0) / 100} 439.82`);
            arc.style.opacity = meter.value ? '1' : '0';
        });
    }
    window.CloudGuardMeters = { model, latestSnapshot, mount, update, state };
})();
/* End scan meters. */
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
                        <span class="cg-brand-subtitle">Scanner workspace</span>
                    </span>
                </a>
                <nav class="cg-nav" aria-label="Primary navigation">
                    ${nav.map(([key, label]) => `
                        <a class="cg-nav-link ${page === key ? "active" : ""}" href="${routes[key]}" ${page === key ? 'aria-current="page"' : ''} ${key === 'grc' ? 'title="Open the separate GRC platform"' : ''}>${label}</a>
                    `).join("")}
                </nav>
                <div class="cg-actions">
                    <a class="cg-primary-link" href="${routes.home}">New scan</a>
                </div>
            </div>
        `;
        document.body.prepend(shell);
        if (page === 'home' || page === 'dashboard') {
            window.CloudGuardMeters.mount(document.querySelector(page === 'home' ? '.content-grid' : '.stats-grid'));
            if (page === 'home') {
                window.CloudGuardMeters.latestSnapshot().then(snapshot => {
                    if (!snapshot) { window.CloudGuardMeters.state('empty'); return; }
                    window.CloudGuardMeters.update(snapshot.summary, snapshot.findings, `Latest completed scan #${snapshot.scanId} · Earlier scans are in History`);
                }).catch(() => window.CloudGuardMeters.state('error'));
            }
        }
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", addShell);
    } else {
        addShell();
    }
})();
