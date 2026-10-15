// Global Application State
const state = {
  currentRole: 'student', // 'student', 'instructor', 'attacker'
  keys: {
    student: null,
    instructor: null,
    attacker: null
  },
  activeIdentity: {
    name: 'Alice Wonderland',
    pubKey: '',
    privKey: ''
  },
  courses: [],
  invites: [],
  blocks: []
};

// Initialize application on DOM ready
document.addEventListener('DOMContentLoaded', async () => {
  await loadDemoKeys();
  await loadCourses();
  await loadLedgerBlocks();
  await runGlobalAudit();
});

// Switch UI Tabs
function switchTab(tabId) {
  document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(el => el.classList.remove('active'));

  const targetPane = document.getElementById(tabId);
  if (targetPane) targetPane.classList.add('active');

  const navButtons = document.querySelectorAll('.nav-btn');
  navButtons.forEach(btn => {
    if (btn.getAttribute('onclick')?.includes(tabId)) {
      btn.classList.add('active');
    }
  });

  if (tabId === 'tab-ledger') loadLedgerBlocks();
  if (tabId === 'tab-student') loadCourses();
}

// =====================================================================
// IDENTITY & DEMO KEYS
// =====================================================================

async function loadDemoKeys() {
  try {
    const res = await fetch('/api/simulation/demo-keys');
    const data = await res.json();
    state.keys.instructor = data.instructor;
    state.keys.student = data.student_alice;
    state.keys.attacker = data.attacker_eve;

    // Default to Alice as active student
    state.activeIdentity = {
      name: data.student_alice.name,
      pubKey: data.student_alice.pub_key,
      privKey: data.student_alice.priv_key
    };

    updateIdentityDisplays();
  } catch (err) {
    console.error('Error loading demo keys:', err);
  }
}

function updateIdentityDisplays() {
  const pubDisplay = document.getElementById('student-pubkey-display');
  const privDisplay = document.getElementById('student-privkey-display');
  if (pubDisplay) pubDisplay.textContent = state.activeIdentity.pubKey;
  if (privDisplay) privDisplay.textContent = state.activeIdentity.privKey;

  const roleName = document.getElementById('role-name-display');
  const rolePub = document.getElementById('role-pubkey-display');
  const rolePriv = document.getElementById('role-privkey-display');
  if (roleName) roleName.value = state.activeIdentity.name;
  if (rolePub) rolePub.value = state.activeIdentity.pubKey;
  if (rolePriv) rolePriv.value = state.activeIdentity.privKey;

  const invitePubInput = document.getElementById('invite-student-pubkey');
  if (invitePubInput && !invitePubInput.value) {
    invitePubInput.value = state.activeIdentity.pubKey;
  }
}

async function generateNewIdentity() {
  try {
    const newKeys = await CryptoClient.generateKeyPair();
    state.activeIdentity = {
      name: 'Custom WebCrypto User',
      pubKey: newKeys.publicKeyHex,
      privKey: newKeys.privateKeyHex
    };
    updateIdentityDisplays();
    alert('Generated new ECDSA (P-256) Keypair client-side via WebCrypto!');
  } catch (err) {
    alert('WebCrypto generation error: ' + err.message);
  }
}

function switchIdentityRole(role) {
  if (role === 'student') {
    state.activeIdentity = {
      name: state.keys.student.name,
      pubKey: state.keys.student.pub_key,
      privKey: state.keys.student.priv_key
    };
  } else if (role === 'instructor') {
    state.activeIdentity = {
      name: state.keys.instructor.name,
      pubKey: state.keys.instructor.pub_key,
      privKey: state.keys.instructor.priv_key
    };
  } else if (role === 'attacker') {
    state.activeIdentity = {
      name: state.keys.attacker.name,
      pubKey: state.keys.attacker.pub_key,
      privKey: state.keys.attacker.priv_key
    };
  }
  updateIdentityDisplays();
  loadCourses();
  alert(`Switched active identity to: ${state.activeIdentity.name}`);
}

// =====================================================================
// COURSES & INVITATIONS
// =====================================================================

async function loadCourses() {
  try {
    const res = await fetch('/api/courses');
    state.courses = await res.json();

    // Populate instructor course select
    const select = document.getElementById('invite-course-select');
    if (select) {
      select.innerHTML = state.courses.map(c => 
        `<option value="${c.course_id}">${c.course_code}: ${c.title}</option>`
      ).join('');
    }

    // Fetch invitations for active student
    if (state.activeIdentity.pubKey) {
      const invRes = await fetch(`/api/invites/student/${state.activeIdentity.pubKey}`);
      state.invites = await invRes.json();
    }

    renderCourses();
  } catch (err) {
    console.error('Error fetching courses:', err);
  }
}

function renderCourses() {
  const container = document.getElementById('courses-list');
  if (!container) return;

  if (state.courses.length === 0) {
    container.innerHTML = `<div style="color: var(--text-muted);">No courses registered yet.</div>`;
    return;
  }

  container.innerHTML = state.courses.map(course => {
    const statusClass = course.status === 'OPEN' ? 'badge-open' : (course.status === 'SCHEDULED' ? 'badge-sched' : 'badge-closed');
    const hasInvite = state.invites.some(inv => inv.course_id === course.course_id);
    
    return `
      <div class="card" style="margin-bottom: 0;">
        <div class="card-header">
          <div>
            <div style="font-size: 0.8rem; color: var(--accent-cyan); font-family: var(--font-mono); font-weight: 700;">
              ${course.course_code}
            </div>
            <div class="card-title" style="font-size: 1.1rem; margin-top: 0.2rem;">
              ${course.title}
            </div>
          </div>
          <span class="badge ${statusClass}">${course.status}</span>
        </div>

        <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1rem;">
          ${course.description}
        </p>

        <div style="font-size: 0.8rem; margin-bottom: 1rem; display: flex; flex-direction: column; gap: 0.3rem;">
          <div>👨‍🏫 <strong>Instructor:</strong> ${course.instructor_name}</div>
          <div>👥 <strong>Seats:</strong> ${course.enrolled_count} / ${course.capacity}</div>
          <div>⏰ <strong>Schedule Window:</strong></div>
          <div style="font-family: var(--font-mono); color: var(--accent-cyan); font-size: 0.75rem;">
            From: ${new Date(course.schedule_start).toLocaleString()}<br>
            Until: ${new Date(course.schedule_end).toLocaleString()}
          </div>
        </div>

        <div style="border-top: 1px solid var(--border-color); padding-top: 1rem; display: flex; justify-content: space-between; align-items: center;">
          <span class="badge ${hasInvite ? 'badge-open' : 'badge-sched'}">
            ${hasInvite ? '✓ Invitation Validated' : '⏳ Invitation Needed'}
          </span>

          <div style="display: flex; gap: 0.5rem;">
            ${!hasInvite ? `
              <button class="btn btn-secondary btn-sm" onclick="quickClaimInvite('${course.course_id}')">
                Request Invite
              </button>
            ` : `
              <button class="btn btn-primary btn-sm" onclick="submitEnrollment('${course.course_id}')" ${course.status !== 'OPEN' ? 'title="Course window not open"' : ''}>
                ✍️ Sign & Enroll
              </button>
            `}
          </div>
        </div>
      </div>
    `;
  }).join('');
}

async function quickClaimInvite(courseId) {
  try {
    const res = await fetch('/api/invites/issue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        course_id: courseId,
        student_public_key: state.activeIdentity.pubKey
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Failed to claim invitation');
    alert(`Cryptographic Invitation certificate issued and signed by instructor for ${courseId}!`);
    await loadCourses();
  } catch (err) {
    alert('Error claiming invite: ' + err.message);
  }
}

async function handleCreateCourse(event) {
  event.preventDefault();
  const code = document.getElementById('new-course-code').value;
  const title = document.getElementById('new-course-title').value;
  const desc = document.getElementById('new-course-desc').value;
  const start = document.getElementById('new-course-start').value;
  const end = document.getElementById('new-course-end').value;
  const capacity = parseInt(document.getElementById('new-course-capacity').value);

  if (!start || !end) {
    alert('Please specify enrollment start and end schedules.');
    return;
  }

  const payload = {
    course_code: code,
    title: title,
    description: desc,
    instructor_name: state.keys.instructor.name,
    instructor_public_key: state.keys.instructor.pub_key,
    capacity: capacity,
    schedule_start: new Date(start).toISOString(),
    schedule_end: new Date(end).toISOString()
  };

  try {
    const res = await fetch('/api/courses', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Failed to create course');

    alert(`Course ${data.course_code} created on ledger!`);
    document.getElementById('create-course-form').reset();
    await loadCourses();
    switchTab('tab-student');
  } catch (err) {
    alert('Error creating course: ' + err.message);
  }
}

async function handleIssueInvite(event) {
  event.preventDefault();
  const courseId = document.getElementById('invite-course-select').value;
  const studentPub = document.getElementById('invite-student-pubkey').value;

  try {
    const res = await fetch('/api/invites/issue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        course_id: courseId,
        student_public_key: studentPub
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Failed to issue invite');

    const resultBox = document.getElementById('invite-result-box');
    const resultContent = document.getElementById('invite-result-content');
    resultBox.style.display = 'block';
    resultContent.textContent = JSON.stringify(data, null, 2);
    alert('Invitation certificate signed and registered!');
    await loadCourses();
  } catch (err) {
    alert('Error issuing invite: ' + err.message);
  }
}

// =====================================================================
// STUDENT ENROLLMENT SUBMISSION (CLIENT-SIDE SIGNING)
// =====================================================================

async function submitEnrollment(courseId) {
  const invite = state.invites.find(inv => inv.course_id === courseId);
  if (!invite) {
    alert('No valid invitation found for this course.');
    return;
  }

  const detailsInput = document.getElementById('student-details-input').value;

  try {
    // 1. Client-side AES-256-GCM symmetric encryption
    const enc = await CryptoClient.encryptAESGCM(detailsInput);

    // 2. Prepare transaction payload
    const nowIso = new Date().toISOString();
    const nonce = 'tx_' + Math.random().toString(36).substring(2, 12);

    const rawTxDict = {
      course_id: courseId,
      student_public_key: state.activeIdentity.pubKey,
      encrypted_details: enc.ciphertextHex,
      iv_hex: enc.ivHex,
      tag_hex: enc.tagHex,
      invite_id: invite.invite_id,
      admin_signature: invite.admin_signature,
      timestamp: nowIso,
      nonce: nonce
    };

    // Canonical JSON stringify
    const txCanonicalJson = CryptoClient.canonicalJson(rawTxDict);
    const txId = await CryptoClient.sha256(txCanonicalJson);

    // 3. Client-side ECDSA Digital Signature using Student's Private Key
    const studentSig = await CryptoClient.signMessage(state.activeIdentity.privKey, txCanonicalJson);

    const payload = {
      tx_id: txId,
      course_id: courseId,
      student_public_key: state.activeIdentity.pubKey,
      encrypted_details: enc.ciphertextHex,
      iv_hex: enc.ivHex,
      tag_hex: enc.tagHex,
      invite_certificate: invite,
      timestamp: nowIso,
      nonce: nonce,
      student_signature: studentSig
    };

    // 4. Submit to Ledger API
    const res = await fetch('/api/enrollments/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const result = await res.json();
    if (!res.ok) throw new Error(result.detail || 'Enrollment rejected');

    // Display receipt
    const receiptBox = document.getElementById('enrollment-receipt-box');
    const receiptContent = document.getElementById('receipt-content');
    receiptBox.style.display = 'block';
    receiptContent.textContent = JSON.stringify(result, null, 2);

    alert('Enrollment cryptographically verified and sealed into Blockchain!');
    await loadCourses();
    await loadLedgerBlocks();
    await runGlobalAudit();
  } catch (err) {
    alert('Enrollment submission error: ' + err.message);
  }
}

// =====================================================================
// BLOCKCHAIN EXPLORER & MERKLE TREE
// =====================================================================

async function loadLedgerBlocks() {
  try {
    const res = await fetch('/api/ledger/blocks');
    state.blocks = await res.json();
    renderBlockchainStream();
  } catch (err) {
    console.error('Error fetching ledger blocks:', err);
  }
}

function renderBlockchainStream() {
  const container = document.getElementById('blockchain-stream-container');
  if (!container) return;

  container.innerHTML = state.blocks.map((block, idx) => {
    const isGenesis = block.header.index === 0;
    const isTampered = block._isTampered || false;

    return `
      <div class="block-node ${isTampered ? 'tampered' : 'valid'}" onclick="inspectBlock(${block.header.index})">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
          <span style="font-weight: 800; font-size: 1.1rem; color: var(--accent-cyan);">
            ${isGenesis ? '⚡ Genesis Block #0' : `📦 Block #${block.header.index}`}
          </span>
          <span class="badge ${isTampered ? 'badge-closed' : 'badge-open'}">
            ${isTampered ? 'TAMPERED' : 'VALID'}
          </span>
        </div>

        <div style="font-size: 0.78rem; display: flex; flex-direction: column; gap: 0.4rem;">
          <div>
            <span style="color: var(--text-dim);">PREV HASH:</span>
            <div class="hash-pill">${block.header.prev_hash.substring(0, 16)}...${block.header.prev_hash.substring(56)}</div>
          </div>
          <div>
            <span style="color: var(--text-dim);">MERKLE ROOT:</span>
            <div class="hash-pill">${block.header.merkle_root.substring(0, 16)}...</div>
          </div>
          <div>
            <span style="color: var(--text-dim);">BLOCK HASH:</span>
            <div class="hash-pill" style="color: var(--accent-emerald);">${block.header.block_hash.substring(0, 16)}...</div>
          </div>
          <div style="color: var(--text-muted); margin-top: 0.3rem;">
            📄 <strong>Transactions:</strong> ${block.transactions.length}
          </div>
        </div>
      </div>
      ${idx < state.blocks.length - 1 ? '<div class="block-link">→</div>' : ''}
    `;
  }).join('');
}

function inspectBlock(index) {
  const block = state.blocks.find(b => b.header.index === index);
  if (!block) return;

  const card = document.getElementById('block-inspector-card');
  const title = document.getElementById('inspector-title');
  const content = document.getElementById('inspector-content');

  card.style.display = 'block';
  title.textContent = `Inspector: Block #${block.header.index} (Hash: ${block.header.block_hash.substring(0, 16)}...)`;
  content.textContent = JSON.stringify(block, null, 2);
}

async function mineBlock() {
  try {
    const res = await fetch('/api/enrollments/mine', { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Mining failed');
    alert(`Mined new Block #${data.header.index}!`);
    await loadLedgerBlocks();
    await runGlobalAudit();
  } catch (err) {
    alert(err.message);
  }
}

// =====================================================================
// ATTACK & TAMPER SIMULATION LAB (ACADEMIC DEMONSTRATION)
// =====================================================================

function logAuditTerminal(message) {
  const terminal = document.getElementById('audit-results-terminal');
  if (terminal) {
    const time = new Date().toLocaleTimeString();
    terminal.textContent = `[${time}] ${message}\n\n` + terminal.textContent;
  }
}

// ATTACK 1: DEVELOPER INJECTS FAKE PRE-VALIDATED STUDENT DIRECTLY IN DB
async function runAttack_DeveloperDbInjection() {
  logAuditTerminal(">>> EXECUTING ATTACK 1: Rogue Developer directly injects fake student 'Eve Malicious' into the DB 'invitations' table without Admin Private Key...");
  try {
    const res = await fetch('/api/simulation/inject-fake-invite-db', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        course_id: 'CS-801',
        fake_student_name: 'Eve (Rogue Developer)'
      })
    });
    const result = await res.json();
    
    logAuditTerminal(`[ATTACK RESULT]: Database row successfully inserted by rogue developer.\n` +
      `[CRYPTOGRAPHIC VERIFICATION]: is_valid = ${result.cryptographic_verification.is_valid}\n` +
      `[MESSAGE]: ${result.cryptographic_verification.audit_message}\n` +
      `[CONCLUSION]: ${result.conclusion}`
    );

    await runGlobalAudit();
  } catch (err) {
    logAuditTerminal(`[ERROR]: ${err.message}`);
  }
}

// ATTACK 2: DEVELOPER INJECTS ENROLLEE DIRECTLY INTO BLOCK
async function runAttack_DeveloperBlockInjection() {
  logAuditTerminal(">>> EXECUTING ATTACK 2: Rogue Developer attempts to inject unauthorized student into Block #1 transaction list...");
  try {
    const res = await fetch('/api/simulation/inject-student-block', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        block_index: 1,
        fake_student_name: 'Eve Malicious (Rogue Developer)'
      })
    });
    const result = await res.json();
    logAuditTerminal(`[INJECTION EXECUTED]: Injected unauthorized student into Block #1 memory.\nRunning cryptographic verification...`);
    await loadLedgerBlocks();
    await runGlobalAudit();
  } catch (err) {
    logAuditTerminal(`[ERROR]: ${err.message}`);
  }
}

// ATTACK 3: RECORD TAMPERING IN COMMITTED TRANSACTION
async function runAttack_TamperTransactionData() {
  logAuditTerminal(">>> EXECUTING ATTACK 3: Rogue Developer directly alters Alice's encrypted payload inside Block #1 in storage...");
  try {
    const res = await fetch('/api/simulation/tamper-tx-data', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        block_index: 1,
        tx_index: 0,
        field: 'encrypted_details',
        fake_value: 'DEADBEEF_TAMPERED_BY_DEVELOPER'
      })
    });
    const result = await res.json();
    logAuditTerminal(`[TAMPER EXECUTED]: Modified Block #1 transaction field 'encrypted_details' to forged value.\nRunning cryptographic verification...`);
    await loadLedgerBlocks();
    await runGlobalAudit();
  } catch (err) {
    logAuditTerminal(`[ERROR]: ${err.message}`);
  }
}

// ATTACK 4: FRONT-RUNNING / TIME-LOCK BYPASS
async function runAttack_FrontRunning() {
  logAuditTerminal(">>> EXECUTING ATTACK 4: Attempting to bypass time-lock by submitting enrollment to CS-902 before scheduled start...");
  try {
    // Generate valid invite for CS-902
    const invRes = await fetch('/api/invites/issue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        course_id: 'CS-902',
        student_public_key: state.activeIdentity.pubKey
      })
    });
    const invite = await invRes.json();

    // Now submit enrollment prematurely
    const enc = await CryptoClient.encryptAESGCM("Eager Student Front-Running");
    const nowIso = new Date().toISOString();
    const nonce = 'early_' + Math.random().toString(36).substring(2, 10);

    const rawTxDict = {
      course_id: 'CS-902',
      student_public_key: state.activeIdentity.pubKey,
      encrypted_details: enc.ciphertextHex,
      iv_hex: enc.ivHex,
      tag_hex: enc.tagHex,
      invite_id: invite.invite_id,
      admin_signature: invite.admin_signature,
      timestamp: nowIso,
      nonce: nonce
    };
    const txJson = CryptoClient.canonicalJson(rawTxDict);
    const txId = await CryptoClient.sha256(txJson);
    const sig = await CryptoClient.signMessage(state.activeIdentity.privKey, txJson);

    const txPayload = {
      tx_id: txId,
      course_id: 'CS-902',
      student_public_key: state.activeIdentity.pubKey,
      encrypted_details: enc.ciphertextHex,
      iv_hex: enc.ivHex,
      tag_hex: enc.tagHex,
      invite_certificate: invite,
      timestamp: nowIso,
      nonce: nonce,
      student_signature: sig
    };

    const res = await fetch('/api/enrollments/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(txPayload)
    });
    const result = await res.json();

    if (!res.ok) {
      logAuditTerminal(`[DEFENSE SUCCESSFUL]: Early enrollment was rejected!\n[SERVER RESPONSE]: ${result.detail}`);
    } else {
      logAuditTerminal(`[WARNING]: Early enrollment went through: ${JSON.stringify(result)}`);
    }
  } catch (err) {
    logAuditTerminal(`[DEFENSE SUCCESSFUL]: Early enrollment rejected by time-lock constraint:\n${err.message}`);
  }
}

// ATTACK 5: REPLAY ATTACK (DUPLICATE NONCE)
async function runAttack_Replay() {
  logAuditTerminal(">>> EXECUTING ATTACK 5: Intercepting and resubmitting a previously committed student enrollment transaction...");
  try {
    if (state.blocks.length < 2 || state.blocks[1].transactions.length === 0) {
      logAuditTerminal("[NOTICE]: No transactions available in Block #1 to replay. Seed or submit an enrollment first.");
      return;
    }

    const targetTx = state.blocks[1].transactions[0];
    const res = await fetch('/api/enrollments/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(targetTx)
    });
    const result = await res.json();

    if (!res.ok) {
      logAuditTerminal(`[DEFENSE SUCCESSFUL]: Replay attack intercepted and stopped!\n[REASON]: ${result.detail}`);
    } else {
      logAuditTerminal(`[WARNING]: Replay accepted unexpectedly.`);
    }
  } catch (err) {
    logAuditTerminal(`[DEFENSE SUCCESSFUL]: Replay rejected: ${err.message}`);
  }
}

// ATTACK 6: BLOCK HASH CORRUPTION
async function runAttack_CorruptHash() {
  logAuditTerminal(">>> EXECUTING ATTACK 6: Corrupting Block #1 header hash in database storage...");
  try {
    const res = await fetch('/api/simulation/corrupt-block-header?block_index=1', { method: 'POST' });
    const result = await res.json();
    logAuditTerminal(`[CORRUPTION INJECTED]: Changed Block #1 hash from ${result.old_hash} to ${result.corrupted_hash}`);
    await loadLedgerBlocks();
    await runGlobalAudit();
  } catch (err) {
    logAuditTerminal(`[ERROR]: ${err.message}`);
  }
}

// GLOBAL AUDIT
async function runGlobalAudit() {
  try {
    const res = await fetch('/api/ledger/audit');
    const report = await res.json();

    const badge = document.getElementById('ledger-status-badge');
    const badgeText = document.getElementById('ledger-status-text');

    if (report.is_valid) {
      badge.className = 'status-badge pristine';
      badgeText.textContent = 'LEDGER: PRISTINE';
      logAuditTerminal(`[AUDIT REPORT: PASSED]\n- Blocks Checked: ${report.total_blocks}\n- Transactions Checked: ${report.total_transactions}\n- Status: 100% Cryptographically Sound (No tampering detected)`);
    } else {
      badge.className = 'status-badge corrupted';
      badgeText.textContent = `LEDGER: CORRUPTED (${report.issues.length} VIOLATIONS)`;

      let issuesLog = `[AUDIT REPORT: TAMPERING & FORGERY DETECTED]\n` +
        `Violations found: ${report.issues.length}\n` +
        `------------------------------------------------------------------------\n`;

      report.issues.forEach((issue, idx) => {
        issuesLog += `[Issue #${idx + 1}] Block #${issue.block_index} - Type: ${issue.issue_type}\n` +
          `Description: ${issue.description}\n` +
          (issue.expected ? `Expected: ${issue.expected}\n` : '') +
          (issue.actual ? `Actual:   ${issue.actual}\n` : '') +
          `------------------------------------------------------------------------\n`;
      });

      logAuditTerminal(issuesLog);
    }

    // Mark blocks in state
    if (state.blocks) {
      state.blocks.forEach(b => {
        const hasIssue = report.issues.some(i => i.block_index === b.header.index);
        b._isTampered = hasIssue;
      });
      renderBlockchainStream();
    }
  } catch (err) {
    console.error('Audit failed:', err);
  }
}

// RESET LEDGER
async function resetLedger() {
  try {
    const res = await fetch('/api/simulation/reset', { method: 'POST' });
    const data = await res.json();
    alert('Blockchain ledger restored to clean state.');
    await loadCourses();
    await loadLedgerBlocks();
    await runGlobalAudit();
  } catch (err) {
    alert('Error resetting ledger: ' + err.message);
  }
}
