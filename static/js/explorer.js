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

function inspectExplorerBlock(index) {
  const block = explorerBlocks.find(b => b.header.index === index);
  if (!block) return;

  const card = document.getElementById('block-inspector-card');
  const title = document.getElementById('inspector-title');
  const content = document.getElementById('inspector-content');

  card.style.display = 'block';
  title.textContent = `Inspector: Block #${block.header.index} (Hash: ${block.header.block_hash.substring(0, 18)}...)`;
  content.textContent = JSON.stringify(block, null, 2);
  card.scrollIntoView({ behavior: 'smooth' });
}

async function runExplorerAudit() {
  try {
    const res = await fetch('/api/ledger/audit');
    const report = await res.json();

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
