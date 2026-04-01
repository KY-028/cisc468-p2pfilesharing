/**
 * app.js — Frontend logic for the P2P File Sharing dashboard.
 *
 * Redesigned for a sidebar-based peer interaction model.
 * Click a peer → see their files, verify them, send/request files.
 */

const POLL_INTERVAL_MS = 3000;

// Currently selected peer
let selectedPeerId = null;
let currentConsentId = null;
let lastData = null;


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
// Helper: Format bytes into a readable size
// ============================================================
function formatSize(bytes) {
    if (bytes === 0) return "0 B";
    const units = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(1) + " " + units[i];
}


// ============================================================
// Helper: Format timestamp
// ============================================================
function formatTime(ts) {
    if (!ts) return "";
    const d = new Date(ts * 1000);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}


// ============================================================
// Security: Escape HTML
// ============================================================
function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
}


// ============================================================
// Determine peer status class for the colored dot
// ============================================================
function getPeerStatusClass(peer) {
    if (peer.online && peer.trusted) return "online-verified";
    if (peer.online && peer.verify_pending) return "online-pending";
    if (peer.online && !peer.trusted) return "online-unverified";
    return "offline";
}

function getPeerStatusLabel(peer) {
    if (peer.online && peer.trusted) return "Verified";
    if (peer.online && peer.verify_pending) return "Pending";
    if (peer.online && !peer.trusted) return "Unverified";
    return "Offline";
}


// ============================================================
// Render: Sidebar peer list
// ============================================================
function renderPeerSidebar(peers) {
    const container = document.getElementById("peer-list");
    if (!peers || peers.length === 0) {
        container.innerHTML = '<p class="empty-state">Searching for peers…</p>';
        return;
    }

    // Sort: online first, then by name
    const sorted = [...peers].sort((a, b) => {
        if (a.online !== b.online) return a.online ? -1 : 1;
        return a.display_name.localeCompare(b.display_name);
    });

    container.innerHTML = sorted.map(p => `
        <div class="peer-sidebar-item ${selectedPeerId === p.peer_id ? 'active' : ''}"
             onclick="selectPeer('${escapeHtml(p.peer_id)}')"
             title="${getPeerStatusLabel(p)}">
            <span class="peer-status-dot ${getPeerStatusClass(p)}"></span>
            <div class="peer-sidebar-info">
                <span class="peer-sidebar-name">${escapeHtml(p.display_name)}</span>
                <span class="peer-sidebar-detail">${escapeHtml(p.address)}:${p.port}</span>
            </div>
        </div>
    `).join("");
}


// ============================================================
// Render: My shared files
// ============================================================
function renderMyFiles(files) {
    const container = document.getElementById("file-list");
    if (!files || files.length === 0) {
        container.innerHTML = '<p class="empty-state">No files shared yet. Place files in the <code>shared/</code> folder.</p>';
        return;
    }
    container.innerHTML = files.map(f => `
        <div class="list-item">
            <div class="list-item-info">
                <span class="list-item-name">📄 ${escapeHtml(f.filename)}</span>
                <span class="list-item-detail">${formatSize(f.size)} · ${f.sha256_hash.substring(0, 12)}…</span>
            </div>
            <button class="btn btn-small btn-secondary"
                    onclick="removeFile('${escapeHtml(f.filename)}')">✕ Remove</button>
        </div>
    `).join("");
}


// ============================================================
// Render: Consent requests
// ============================================================
function renderConsents(consents) {
    const section = document.getElementById("consent-section");
    const container = document.getElementById("consent-list");

    if (!consents || consents.length === 0) {
        container.innerHTML = '<p class="empty-state">No pending requests.</p>';
        section.style.display = "";
        return;
    }

    // Show the section prominently
    section.style.display = "";
    container.innerHTML = consents.map(c => `
        <div class="list-item consent-item">
            <div class="list-item-info">
                <span class="list-item-name">
                    <strong>${escapeHtml(c.peer_name)}</strong>
                    wants to ${c.action === "file_send" ? "send you" : "request"}
                    <code>${escapeHtml(c.filename)}</code>
                </span>
            </div>
            <div class="consent-actions">
                <button class="btn btn-small btn-success"
                        onclick="showConsentModal('${c.request_id}', '${escapeHtml(c.peer_name)}', '${c.action}', '${escapeHtml(c.filename)}')">
                    Review
                </button>
            </div>
        </div>
    `).join("");
}


// ============================================================
// Render: Status log
// ============================================================
function renderStatusLog(logs) {
    const container = document.getElementById("status-log");
    if (!logs || logs.length === 0) {
        container.innerHTML = '<p class="empty-state">No activity yet.</p>';
        return;
    }
    // Show last 20
    container.innerHTML = logs.slice(0, 20).map(s => `
        <div class="status-entry ${s.level}">
            <span class="status-dot"></span>
            <span class="status-text">${escapeHtml(s.message)}</span>
            <span class="status-time">${formatTime(s.timestamp)}</span>
        </div>
    `).join("");
}


// ============================================================
// Peer Selection — show peer detail view
// ============================================================
function selectPeer(peerId) {
    selectedPeerId = peerId;

    // Switch views
    document.getElementById("view-home").classList.remove("active");
    document.getElementById("view-peer").classList.add("active");

    // Update sidebar active state
    document.querySelectorAll(".peer-sidebar-item").forEach(el => {
        el.classList.remove("active");
    });

    // Find and activate the correct sidebar item
    const items = document.querySelectorAll(".peer-sidebar-item");
    items.forEach(el => {
        if (el.getAttribute("onclick").includes(peerId)) {
            el.classList.add("active");
        }
    });

    updatePeerDetailView();

    // Auto-fetch file list from this peer
    fetchPeerFiles(peerId);
}

function goBackHome() {
    selectedPeerId = null;
    document.getElementById("view-peer").classList.remove("active");
    document.getElementById("view-home").classList.add("active");
}


// ============================================================
// Update the peer detail view with current data
// ============================================================
function updatePeerDetailView() {
    if (!lastData || !selectedPeerId) return;

    const peer = lastData.peers.find(p => p.peer_id === selectedPeerId);
    if (!peer) {
        goBackHome();
        return;
    }

    document.getElementById("peer-detail-name").textContent = peer.display_name;
    document.getElementById("peer-detail-id").textContent = peer.peer_id;
    document.getElementById("peer-detail-address").textContent = `${peer.address}:${peer.port}`;
    document.getElementById("peer-detail-fingerprint").textContent = peer.fingerprint;

    // Status badge
    const badge = document.getElementById("peer-detail-badge");
    badge.className = "status-badge";
    if (peer.online && peer.trusted) {
        badge.classList.add("online");
        badge.textContent = "Verified · Online";
    } else if (peer.online) {
        badge.classList.add("unverified");
        badge.textContent = "Unverified · Online";
    } else {
        badge.classList.add("offline");
        badge.textContent = "Offline";
    }

    // Trusted indicator
    const trustedEl = document.getElementById("peer-detail-trusted");
    if (peer.trusted) {
        trustedEl.innerHTML = '<span class="status-badge verified">✓ Verified</span>';
    } else if (peer.verify_pending) {
        trustedEl.innerHTML = '<span class="status-badge pending">⏳ Waiting for peer…</span>';
    } else {
        trustedEl.innerHTML = '<span class="status-badge unverified">Not Verified</span>';
    }

    // Verify button state
    const verifyBtn = document.getElementById("btn-verify-peer");
    if (peer.trusted) {
        verifyBtn.textContent = "✓ Already Verified";
        verifyBtn.disabled = true;
        verifyBtn.classList.add("btn-secondary");
        verifyBtn.classList.remove("btn-primary");
    } else if (peer.verify_pending) {
        verifyBtn.textContent = "⏳ Waiting for Peer…";
        verifyBtn.disabled = true;
        verifyBtn.classList.add("btn-secondary");
        verifyBtn.classList.remove("btn-primary");
    } else if (!peer.online) {
        verifyBtn.textContent = "🔐 Peer Offline";
        verifyBtn.disabled = true;
        verifyBtn.classList.add("btn-secondary");
        verifyBtn.classList.remove("btn-primary");
    } else {
        verifyBtn.textContent = "🔐 Verify Peer";
        verifyBtn.disabled = false;
        verifyBtn.classList.remove("btn-secondary");
        verifyBtn.classList.add("btn-primary");
    }

    // Fetch files button state
    const fetchBtn = document.getElementById("btn-fetch-files");
    if (!peer.online) {
        fetchBtn.textContent = "📄 Peer Offline";
        fetchBtn.disabled = true;
    } else {
        fetchBtn.textContent = "📄 Fetch Their File List";
        fetchBtn.disabled = false;
    }

    // Render peer's files from manifests
    renderPeerFiles(selectedPeerId);

    // Render "send file" options
    renderSendFileOptions(selectedPeerId);
}


// ============================================================
// Render: Peer's available files (from manifests)
// ============================================================
function renderPeerFiles(peerId) {
    const container = document.getElementById("peer-file-list");
    if (!lastData) return;

    const files = lastData.peer_files[peerId];
    if (!files || files.length === 0) {
        container.innerHTML = '<p class="empty-state">No file list available. Click "Fetch Their File List" to see available files.</p>';
        return;
    }

    container.innerHTML = files.map(f => `
        <div class="list-item">
            <div class="list-item-info">
                <span class="list-item-name">📄 ${escapeHtml(f.filename)}</span>
                <span class="list-item-detail">${formatSize(f.size)} · ${f.sha256_hash.substring(0, 12)}…</span>
            </div>
            <button class="btn btn-request"
                    onclick="requestFileFromPeer('${escapeHtml(peerId)}', '${escapeHtml(f.filename)}')">
                ↓ Request
            </button>
        </div>
    `).join("");
}


// ============================================================
// Render: Send file options (my files → send to selected peer)
// ============================================================
function renderSendFileOptions(peerId) {
    const container = document.getElementById("send-file-list");
    if (!lastData) return;

    const peer = lastData.peers.find(p => p.peer_id === peerId);
    const files = lastData.shared_files;

    if (!files || files.length === 0) {
        container.innerHTML = '<p class="empty-state">No shared files to send. Add files to your <code>shared/</code> folder.</p>';
        return;
    }

    if (!peer || !peer.online) {
        container.innerHTML = '<p class="empty-state">Peer is offline. Cannot send files.</p>';
        return;
    }

    container.innerHTML = files.map(f => `
        <div class="list-item">
            <div class="list-item-info">
                <span class="list-item-name">📄 ${escapeHtml(f.filename)}</span>
                <span class="list-item-detail">${formatSize(f.size)}</span>
            </div>
            <button class="btn btn-send"
                    onclick="sendFileToPeer('${escapeHtml(peerId)}', '${escapeHtml(f.filename)}')">
                ↑ Send
            </button>
        </div>
    `).join("");
}


// ============================================================
// Actions
// ============================================================
async function fetchPeerFiles(peerId) {
    const peer = lastData?.peers.find(p => p.peer_id === peerId);
    if (peer && !peer.online) {
        // Still show cached manifest if available
        renderPeerFiles(peerId);
        return;
    }
    const result = await apiPost("/api/request-file-list", { peer_id: peerId });
    if (!result.ok) {
        console.warn("Failed to fetch file list:", result.error);
    }
    // The response will arrive async and be stored in manifests
    // Next poll will pick it up
    setTimeout(pollStatus, 1000);
}

async function requestFileFromPeer(peerId, filename) {
    const result = await apiPost("/api/request-file", { peer_id: peerId, filename });
    if (result.ok) {
        // Status will update via polling
    }
    await pollStatus();
}

async function sendFileToPeer(peerId, filename) {
    const result = await apiPost("/api/send-file", { peer_id: peerId, filename });
    if (result.ok) {
        // Status will update via polling
    }
    await pollStatus();
}

async function verifyPeer(peerId) {
    const btn = document.getElementById("btn-verify-peer");
    btn.textContent = "🔐 Connecting…";
    btn.disabled = true;

    const result = await apiPost("/api/verify-peer", { peer_id: peerId });

    if (result.ok && result.already_verified) {
        btn.textContent = "✓ Already Verified";
        btn.classList.add("btn-secondary");
        btn.classList.remove("btn-primary");
        await pollStatus();
        return;
    }

    if (result.ok && result.verification_code) {
        // Show verification modal with the code
        showVerifyModal(peerId, result.verification_code,
                        result.my_fingerprint, result.their_fingerprint);
        btn.textContent = "🔐 Verify Peer";
        btn.disabled = false;
    } else {
        btn.textContent = "🔐 Verify Peer";
        btn.disabled = false;
        await pollStatus();
    }
}

// ============================================================
// Verification Code Modal
// ============================================================
let verifyingPeerId = null;

function showVerifyModal(peerId, code, myFp, theirFp) {
    verifyingPeerId = peerId;

    const peer = lastData?.peers.find(p => p.peer_id === peerId);
    const peerName = peer ? peer.display_name : peerId;

    document.getElementById("verify-peer-name").textContent = peerName;
    document.getElementById("verify-code-display").textContent = code;
    document.getElementById("verify-my-fp").textContent = myFp;
    document.getElementById("verify-their-fp").textContent = theirFp;
    document.getElementById("verify-modal").classList.remove("hidden");
}

function hideVerifyModal() {
    document.getElementById("verify-modal").classList.add("hidden");
    verifyingPeerId = null;
}

async function confirmVerification() {
    if (!verifyingPeerId) return;
    const peerId = verifyingPeerId;
    hideVerifyModal();
    await apiPost("/api/confirm-verify", { peer_id: peerId });
    await pollStatus();
}

async function rejectVerification() {
    if (!verifyingPeerId) return;
    const peerId = verifyingPeerId;
    hideVerifyModal();
    await apiPost("/api/reject-verify", { peer_id: peerId });
    await pollStatus();
}

async function removeFile(filename) {
    await apiPost("/api/remove-shared-file", { filename });
    await pollStatus();
}

async function scanFiles() {
    await apiPost("/api/scan-shared");
    await pollStatus();
}


// ============================================================
// Consent Modal
// ============================================================
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
    await pollStatus();
}


// ============================================================
// Poll: Fetch status and re-render
// ============================================================
async function pollStatus() {
    try {
        const resp = await fetch("/api/status");
        const data = await resp.json();
        lastData = data;

        // Update identity
        document.getElementById("identity-peer-id").textContent = data.peer_id;
        document.getElementById("identity-fingerprint").textContent = data.fingerprint;

        // Update sidebar
        renderPeerSidebar(data.peers);

        // Update home view panels
        renderMyFiles(data.shared_files);
        renderConsents(data.pending_consents);
        renderStatusLog(data.status_log);

        // Update peer detail view if a peer is selected
        if (selectedPeerId) {
            updatePeerDetailView();
        }

        // Show verification modal if there is a pending verification
        if (data.pending_verifications && data.pending_verifications.length > 0) {
            const pv = data.pending_verifications[0];
            // Only show if it's not already showing for this peer
            if (verifyingPeerId !== pv.peer_id && document.getElementById("verify-modal").classList.contains("hidden")) {
                showVerifyModal(pv.peer_id, pv.code, pv.my_fingerprint, pv.their_fingerprint);
            }
        }
    } catch (err) {
        console.error("Poll failed:", err);
    }
}


// ============================================================
// Event Listeners
// ============================================================
document.addEventListener("DOMContentLoaded", () => {
    // Refresh peers
    document.getElementById("btn-refresh-peers").addEventListener("click", async () => {
        await apiPost("/api/refresh-peers");
        await pollStatus();
    });

    // Scan files
    document.getElementById("btn-scan-files").addEventListener("click", scanFiles);

    // Back button
    document.getElementById("btn-back-home").addEventListener("click", goBackHome);

    // Verify peer
    document.getElementById("btn-verify-peer").addEventListener("click", () => {
        if (selectedPeerId) verifyPeer(selectedPeerId);
    });

    // Fetch peer files
    document.getElementById("btn-fetch-files").addEventListener("click", () => {
        if (selectedPeerId) fetchPeerFiles(selectedPeerId);
    });

    // Consent modal buttons
    document.getElementById("modal-accept").addEventListener("click", () => respondConsent("accept"));
    document.getElementById("modal-deny").addEventListener("click", () => respondConsent("deny"));
    document.querySelector("#consent-modal .modal-backdrop").addEventListener("click", hideConsentModal);

    // Verification modal buttons
    document.getElementById("verify-confirm").addEventListener("click", confirmVerification);
    document.getElementById("verify-reject").addEventListener("click", rejectVerification);
    document.getElementById("verify-modal-backdrop").addEventListener("click", hideVerifyModal);

    // Start polling
    pollStatus();
    setInterval(pollStatus, POLL_INTERVAL_MS);
});
