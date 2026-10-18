// Blockchain Explorer Client Script

let explorerBlocks = [];

document.addEventListener('DOMContentLoaded', async () => {
  await loadExplorerChain();
  await runExplorerAudit();
});

async function loadExplorerChain() {
  try {
    const res = await fetch('/api/ledger/blocks');
    explorerBlocks = await res.json();
    renderChainStream();
  } catch (err) {
    console.error('Error loading blocks:', err);
  }
}

function renderChainStream() {
  const container = document.getElementById('explorer-chain-stream');
  if (!container) return;

  if (explorerBlocks.length === 0) {
    container.innerHTML = `<div style="color: var(--text-muted);">No blocks found.</div>`;
    return;
  }

  container.innerHTML = explorerBlocks.map((block, idx) => {
    const isGenesis = block.header.index === 0;
    const isTampered = block._isTampered || false;

    return `
      <div class="block-node ${isTampered ? 'tampered' : 'valid'}" onclick="inspectExplorerBlock(${block.header.index})">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
          <span style="font-weight: 800; font-size: 1.1rem; color: var(--accent-cyan);">
            ${isGenesis ? '⚡ Genesis Block #0' : `📦 Block #${block.header.index}`}
          </span>
          <span class="badge ${isTampered ? 'badge-red' : 'badge-green'}">
            ${isTampered ? 'TAMPERED' : 'VALID'}
          </span>
        </div>

        <div style="font-size: 0.78rem; display: flex; flex-direction: column; gap: 0.35rem;">
          <div>
            <span style="color: var(--text-dim);">PREV HASH:</span>
            <div class="hash-pill">${block.header.prev_hash.substring(0, 14)}...</div>
          </div>
          <div>
            <span style="color: var(--text-dim);">MERKLE ROOT:</span>
            <div class="hash-pill">${block.header.merkle_root.substring(0, 14)}...</div>
          </div>
          <div>
            <span style="color: var(--text-dim);">BLOCK HASH:</span>
            <div class="hash-pill" style="color: var(--accent-emerald);">${block.header.block_hash.substring(0, 14)}...</div>
          </div>
          <div style="color: var(--text-muted); margin-top: 0.3rem;">
            📄 <strong>Transactions:</strong> ${block.transactions.length}
          </div>
        </div>
      </div>
      ${idx < explorerBlocks.length - 1 ? '<div class="block-link">→</div>' : ''}
    `;
  }).join('');
}

let latestAuditReport = null;

async function inspectExplorerBlock(index) {
  const block = explorerBlocks.find(b => b.header.index === index);
  if (!block) return;

  const card = document.getElementById('block-inspector-card');
  const title = document.getElementById('inspector-title');
  const content = document.getElementById('inspector-content');

  card.style.display = 'block';
  title.textContent = `Inspector: Block #${block.header.index} (Hash: ${block.header.block_hash.substring(0, 18)}...)`;

  // Check if this block has audit violations
  const blockIssues = (latestAuditReport && latestAuditReport.issues) ? 
    latestAuditReport.issues.filter(i => i.block_index === block.header.index) : [];

  let html = '';

  // Tamper warning banner
  if (blockIssues.length > 0) {
    html += `
      <div style="background: rgba(239, 68, 68, 0.15); border: 1px solid var(--accent-crimson); border-radius: var(--radius-md); padding: 1rem; margin-bottom: 1.25rem;">
        <div style="color: var(--accent-crimson); font-weight: 700; font-size: 1rem; margin-bottom: 0.5rem; display: flex; align-items: center; gap: 0.5rem;">
          ⚠️ CRYPTOGRAPHIC TAMPER / ATTACK DETECTED IN THIS BLOCK (${blockIssues.length} Violations)
        </div>
        <ul style="margin: 0; padding-left: 1.25rem; font-size: 0.85rem; color: #fca5a5;">
          ${blockIssues.map(issue => `
            <li style="margin-bottom: 0.35rem;">
              <strong>[${issue.issue_type}]</strong>: ${issue.description}
              ${issue.expected ? `<br><span style="font-family: monospace; font-size: 0.78rem; color: #e2e8f0;">Expected: ${issue.expected}</span>` : ''}
              ${issue.actual ? `<br><span style="font-family: monospace; font-size: 0.78rem; color: #f87171;">Actual:   ${issue.actual}</span>` : ''}
            </li>
          `).join('')}
        </ul>
      </div>
    `;
  } else {
    html += `
      <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid var(--accent-emerald); border-radius: var(--radius-md); padding: 0.75rem 1rem; margin-bottom: 1.25rem; color: var(--accent-emerald); font-weight: 600; font-size: 0.88rem;">
        ✓ Cryptographic Integrity Verified: Merkle root, previous block hash chaining, and all digital signatures valid.
      </div>
    `;
  }

  // Header Details Grid
  html += `
    <div style="background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 1rem; margin-bottom: 1.25rem;">
      <h3 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 0.75rem; color: var(--accent-cyan);">⛓️ Block Header Cryptographic Metadata</h3>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 0.75rem; font-size: 0.82rem;">
        <div>
          <span style="color: var(--text-dim);">PREVIOUS BLOCK HASH:</span>
          <div class="hash-pill" style="word-break: break-all; margin-top: 0.2rem;">${block.header.prev_hash}</div>
        </div>
        <div>
          <span style="color: var(--text-dim);">MERKLE ROOT HASH:</span>
          <div class="hash-pill" style="word-break: break-all; margin-top: 0.2rem;">${block.header.merkle_root}</div>
        </div>
        <div>
          <span style="color: var(--text-dim);">BLOCK HASH:</span>
          <div class="hash-pill" style="word-break: break-all; margin-top: 0.2rem; color: var(--accent-emerald);">${block.header.block_hash}</div>
        </div>
        <div>
          <span style="color: var(--text-dim);">TIMESTAMP & NONCE:</span>
          <div style="color: var(--text-main); font-family: monospace; margin-top: 0.2rem;">
            Time: ${block.header.timestamp} | Nonce: ${block.header.nonce}
          </div>
        </div>
      </div>
    </div>
  `;

  // Transactions Section
  html += `
    <div style="margin-bottom: 1.25rem;">
      <h3 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 0.75rem; color: var(--accent-purple);">
        📋 Committed Enrollment Transactions (${block.transactions.length})
      </h3>
  `;

  if (block.transactions.length === 0) {
    html += `<div style="color: var(--text-muted); font-size: 0.85rem; padding: 0.75rem; background: var(--bg-tertiary); border-radius: var(--radius-md);">Genesis Block - No transactions committed.</div>`;
  } else {
    for (let idx = 0; idx < block.transactions.length; idx++) {
      const tx = block.transactions[idx];
      let studentIdHash = 'computing...';
      try {
        studentIdHash = await CryptoClient.sha256(tx.student_public_key);
      } catch (e) {
        studentIdHash = tx.student_public_key.substring(0, 32) + '...';
      }

      html += `
        <div style="background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 1rem; margin-bottom: 0.85rem;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.65rem;">
            <span style="font-weight: 700; color: var(--accent-cyan); font-size: 0.9rem;">
              Transaction #${idx + 1}: Course ${tx.course_id}
            </span>
            <span class="badge badge-purple">E2EE Verified</span>
          </div>

          <div style="display: flex; flex-direction: column; gap: 0.5rem; font-size: 0.82rem;">
            <div>
              <span style="color: var(--text-dim);">TRANSACTION ID (SHA-256):</span>
              <div class="hash-pill">${tx.tx_id}</div>
            </div>
            <div>
              <span style="color: var(--text-dim);">STUDENT PSEUDONYMIZED IDENTITY HASH: SHA-256(PubKey):</span>
              <div class="hash-pill" style="color: var(--accent-cyan);">${studentIdHash}</div>
            </div>
            <div>
              <span style="color: var(--text-dim);">END-TO-END ENCRYPTED PAYLOAD (AES-256-GCM Ciphertext):</span>
              <div class="hash-pill" style="word-break: break-all; color: var(--text-main);">${tx.encrypted_details}</div>
              <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.2rem; font-family: monospace;">
                IV: ${tx.iv_hex} | Auth Tag: ${tx.tag_hex}
              </div>
            </div>
            <div>
              <span style="color: var(--text-dim);">STUDENT ECDSA DIGITAL SIGNATURE (Raw P-256):</span>
              <div class="hash-pill" style="word-break: break-all;">${tx.student_signature}</div>
            </div>
            <div style="background: rgba(0,0,0,0.25); border-radius: var(--radius-sm); padding: 0.6rem; margin-top: 0.35rem;">
              <span style="color: var(--accent-amber); font-weight: 600;">Validated Invite Certificate:</span>
              <div style="font-size: 0.76rem; color: var(--text-muted); margin-top: 0.2rem; font-family: monospace;">
                Certificate ID: ${tx.invite_certificate?.invite_id || 'N/A'}<br>
                Time Lock: [${tx.invite_certificate?.valid_from || 'UNTIMED'} → ${tx.invite_certificate?.valid_until || 'UNTIMED'}]<br>
                Admin Signature: ${(tx.invite_certificate?.admin_signature || '').substring(0, 32)}...
              </div>
            </div>
          </div>
        </div>
      `;
    }
  }

  html += `</div>`;

  // Collapsible Raw JSON Block
  html += `
    <details style="margin-top: 0.5rem;">
      <summary style="cursor: pointer; color: var(--text-muted); font-size: 0.82rem; margin-bottom: 0.5rem;">
        🔍 View Raw Cryptographic Block JSON
      </summary>
      <pre class="code-box" style="max-height: 250px; overflow: auto; margin-top: 0.35rem;">${JSON.stringify(block, null, 2)}</pre>
    </details>
  `;

  content.innerHTML = html;
  card.scrollIntoView({ behavior: 'smooth' });
}

async function runExplorerAudit() {
  try {
    const res = await fetch('/api/ledger/audit');
    const report = await res.json();
    latestAuditReport = report;

    const badge = document.getElementById('explorer-status-badge');
    const badgeText = document.getElementById('explorer-status-text');
    const content = document.getElementById('explorer-audit-content');

    if (report.is_valid) {
      badge.className = 'status-badge pristine';
      badgeText.textContent = 'LEDGER: PRISTINE';
    } else {
      badge.className = 'status-badge corrupted';
      badgeText.textContent = `LEDGER: CORRUPTED (${report.issues.length} ISSUES)`;
    }

    content.textContent = JSON.stringify(report, null, 2);

    // Update block nodes
    explorerBlocks.forEach(b => {
      b._isTampered = report.issues.some(i => i.block_index === b.header.index);
    });
    renderChainStream();
  } catch (err) {
    console.error('Audit failed:', err);
  }
}

async function mineBlock() {
  try {
    const res = await fetch('/api/enrollments/mine', { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Mining failed');
    alert(`Mined new Block #${data.header.index}!`);
    await loadExplorerChain();
    await runExplorerAudit();
  } catch (err) {
    alert(err.message);
  }
}
