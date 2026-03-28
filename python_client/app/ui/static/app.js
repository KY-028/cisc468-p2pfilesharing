/**
 * app.js — Frontend logic for the P2P File Sharing dashboard.
 *
 * Handles:
 *   - Polling the /api/status endpoint to refresh all panels
 *   - Form submissions for adding files, requesting/sending files
 *   - Consent modal interactions
 *   - Status log rendering
 *
 * Reading order: Read this AFTER the HTML templates and routes.py.
 */

// ============================================================
// Configuration
// ============================================================
const POLL_INTERVAL_MS = 3000; // How often to refresh data from the server


// ============================================================
// Helper: POST to an API endpoint with form data
// ============================================================
async function apiPost(url, data = {}) {
    const formData = new FormData();
    for (const [key, value] of Object.entries(data)) {
        formData.append(key, value);
    }
    try {
        const resp = await fetch(url, { method: "POST", body: formData });
        return await resp.json();
    } catch (err) {
        console.error(`API POST ${url} failed:`, err);
        return { ok: false, error: err.message };
    }
}


// ============================================================
// Helper: Format a Unix timestamp into a readable time string
// ============================================================
function formatTime(ts) {
    if (!ts) return "";
    const d = new Date(ts * 1000);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}


// ============================================================
// Render: Peer list panel
// ============================================================
function renderPeers(peers) {
    const container = document.getElementById("peer-list");
    if (!peers || peers.length === 0) {
        container.innerHTML = '<p class="empty-state">No peers discovered yet.</p>';
        return;
    }
    container.innerHTML = peers.map(p => `
        <div class="peer-item">
            <div class="peer-item-info">
                <span class="peer-item-name">${escapeHtml(p.display_name)}</span>
                <span class="peer-item-detail">${escapeHtml(p.address)}:${p.port}</span>
            </div>
            <span class="badge ${p.trusted ? 'badge-success' : 'badge-warning'}">
                ${p.trusted ? 'Trusted' : 'Unverified'}
            </span>
        </div>
    `).join("");
}


// ============================================================
// Render: Shared files panel
// ============================================================
function renderFiles(files) {
    const container = document.getElementById("file-list");
    if (!files || files.length === 0) {
        container.innerHTML = '<p class="empty-state">No files shared yet.</p>';
        return;
    }
    container.innerHTML = files.map(f => `
        <div class="file-item">
            <div class="file-item-info">
                <span class="file-item-name">${escapeHtml(f.filename)}</span>
                <span class="file-item-detail">${formatSize(f.size)} · ${f.sha256_hash.substring(0, 12)}…</span>
            </div>
            <button class="btn btn-sm btn-secondary"
                    onclick="removeFile('${escapeHtml(f.filename)}')">✕</button>
        </div>
    `).join("");
}

function formatSize(bytes) {
    if (bytes === 0) return "0 B";
    const units = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(1) + " " + units[i];
}


// ============================================================
// Render: Consent requests panel
// ============================================================
function renderConsents(consents) {
    const container = document.getElementById("consent-list");
    if (!consents || consents.length === 0) {
        container.innerHTML = '<p class="empty-state">No pending consent requests.</p>';
        return;
    }
    container.innerHTML = consents.map(c => `
        <div class="consent-item">
            <div class="consent-item-info">
                <span class="consent-item-desc">
                    <strong>${escapeHtml(c.peer_name)}</strong> wants to
                    ${c.action === "file_send" ? "send you" : "request"}
                    <code>${escapeHtml(c.filename)}</code>
                </span>
            </div>
            <div class="consent-actions">
                <button class="btn btn-sm btn-primary"
                        onclick="showConsentModal('${c.request_id}', '${escapeHtml(c.peer_name)}', '${c.action}', '${escapeHtml(c.filename)}')">
                    Review
                </button>
            </div>
        </div>
    `).join("");
}


// ============================================================
// Render: Status log panel
// ============================================================
function renderStatusLog(logs) {
    const container = document.getElementById("status-log");
    if (!logs || logs.length === 0) {
        container.innerHTML = '<p class="empty-state">No messages yet.</p>';
        return;
    }
    container.innerHTML = logs.map(s => `
        <div class="status-item ${s.level}">
            <span class="status-dot"></span>
            <span class="status-text">${escapeHtml(s.message)}</span>
            <span class="status-time">${formatTime(s.timestamp)}</span>
        </div>
    `).join("");
}


// ============================================================
// Poll: Fetch status from server and re-render all panels
// ============================================================
async function pollStatus() {
    try {
        const resp = await fetch("/api/status");
        const data = await resp.json();

        // Update identity
        document.getElementById("identity-peer-id").textContent = data.peer_id;
        document.getElementById("identity-fingerprint").textContent = data.fingerprint;

        // Update panels
        renderPeers(data.peers);
        renderFiles(data.shared_files);
        renderConsents(data.pending_consents);
        renderStatusLog(data.status_log);
    } catch (err) {
        console.error("Poll failed:", err);
    }
}


// ============================================================
// Consent Modal
// ============================================================
let currentConsentId = null;

function showConsentModal(requestId, peerName, action, filename) {
    currentConsentId = requestId;
    document.getElementById("modal-peer-name").textContent = peerName;
    document.getElementById("modal-action").textContent =
        action === "file_send" ? "send you the file" : "download your file";
    document.getElementById("modal-filename").textContent = filename;
    document.getElementById("consent-modal").classList.remove("hidden");
}

function hideConsentModal() {
    document.getElementById("consent-modal").classList.add("hidden");
    currentConsentId = null;
}

async function respondConsent(action) {
    if (!currentConsentId) return;
    await apiPost(`/api/consent/${currentConsentId}/${action}`);
    hideConsentModal();
    await pollStatus(); // Refresh immediately
}


// ============================================================
// File actions
// ============================================================
async function removeFile(filename) {
    await apiPost("/api/remove-shared-file", { filename });
    await pollStatus();
}


// ============================================================
// Security: Escape HTML to prevent XSS
// ============================================================
function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
}


// ============================================================
// Event Listeners — wire up forms and buttons on page load
// ============================================================
document.addEventListener("DOMContentLoaded", () => {
    // --- Refresh peers ---
    document.getElementById("btn-refresh-peers").addEventListener("click", async () => {
        await apiPost("/api/refresh-peers");
        await pollStatus();
    });

    // --- Add shared file ---
    document.getElementById("add-file-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const input = document.getElementById("add-file-input");
        const filename = input.value.trim();
        if (!filename) return;
        await apiPost("/api/add-shared-file", { filename });
        input.value = "";
        await pollStatus();
    });

    // --- Request file from peer ---
    document.getElementById("request-file-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const form = e.target;
        const peer_id = form.querySelector('[name="peer_id"]').value.trim();
        const filename = form.querySelector('[name="filename"]').value.trim();
        if (!peer_id || !filename) return;
        await apiPost("/api/request-file", { peer_id, filename });
        form.reset();
        await pollStatus();
    });

    // --- Send file to peer ---
    document.getElementById("send-file-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const form = e.target;
        const peer_id = form.querySelector('[name="peer_id"]').value.trim();
        const filename = form.querySelector('[name="filename"]').value.trim();
        if (!peer_id || !filename) return;
        await apiPost("/api/send-file", { peer_id, filename });
        form.reset();
        await pollStatus();
    });

    // --- Test consent button ---
    document.getElementById("btn-test-consent").addEventListener("click", async () => {
        await apiPost("/api/test-consent");
        await pollStatus();
    });

    // --- Consent modal buttons ---
    document.getElementById("modal-accept").addEventListener("click", () => respondConsent("accept"));
    document.getElementById("modal-deny").addEventListener("click", () => respondConsent("deny"));
    document.querySelector(".modal-backdrop").addEventListener("click", hideConsentModal);

    // --- Start polling ---
    pollStatus();
    setInterval(pollStatus, POLL_INTERVAL_MS);
});
