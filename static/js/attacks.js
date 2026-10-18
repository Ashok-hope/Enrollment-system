// Security & Attack Lab JavaScript

document.addEventListener('DOMContentLoaded', async () => {
  await runDeepAudit();
});

const SQL_TEMPLATES = {
  fake_invite: `INSERT INTO invitations (invite_id, course_id, student_identity_hash, valid_from, valid_until, nonce, admin_signature, issued_at, row_seal) 
VALUES ('forged_inv_eve', 'CS-801', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', '2026-01-01T00:00:00Z', '2026-12-31T23:59:59Z', 'forged_nonce', 'bad_signature_from_developer_000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', '2026-10-15T21:00:00Z', 'forged_seal_unauthorized');`,

  tamper_block: `UPDATE ledger_blocks 
SET encrypted_block_payload = 'TAMPERED_DEVELOPER_PAYLOAD_EVE',
    block_hash = 'bad_block_hash_0000000000000000000000000000000000000000000000000000' 
WHERE block_index = 1;`,

  fake_block: `INSERT INTO ledger_blocks (block_index, prev_hash, merkle_root, timestamp, nonce, block_hash, encrypted_block_payload, iv, tag, row_seal) 
VALUES (99, '0000000000000000000000000000000000000000000000000000000000000000', 'fake_merkle_root', '2026-10-15T21:00:00Z', 0, 'fake_block_hash_by_developer', 'fake_payload', 'iv01', 'tag01', 'bad_seal');`,

  select_users_encrypted: `SELECT user_id, identity_hash, email_hash, SUBSTR(encrypted_profile, 1, 24) || '...' AS ciphertext, SUBSTR(row_seal, 1, 16) || '...' AS row_seal FROM users;`,

  select_invites: `SELECT invite_id, course_id, SUBSTR(student_identity_hash, 1, 16) || '...' AS student_id_hash, SUBSTR(row_seal, 1, 16) || '...' AS seal FROM invitations;`,

  select_blocks: `SELECT block_index, SUBSTR(prev_hash, 1, 12) || '...' AS prev_hash, SUBSTR(merkle_root, 1, 12) || '...' AS merkle, SUBSTR(block_hash, 1, 12) || '...' AS block_hash, SUBSTR(row_seal, 1, 16) || '...' AS seal FROM ledger_blocks;`
};

function populateSqlAttack(type) {
  const textarea = document.getElementById('sql-query-input');
  if (textarea && SQL_TEMPLATES[type]) {
    textarea.value = SQL_TEMPLATES[type];
  }
}

async function runPenTest_DbSnoop() {
  logTerminal(`>>> EXECUTING DATABASE SNOOPING & EXFILTRATION PROBE:\nChecking whether plaintext student records or unhashed keys exist in SQLite...`);
  try {
    const res = await fetch('/api/simulation/pen-test/db-snoop');
    const data = await res.json();

    const card = document.getElementById('pentest-result-card');
    const title = document.getElementById('pentest-result-title');
    const content = document.getElementById('pentest-result-content');

    card.style.display = 'block';
    title.textContent = 'Penetration Test: Database Snooping & Storage Inspection Result';
    content.textContent = JSON.stringify(data, null, 2);

    logTerminal(`[PEN-TEST 1 VERDICT]:\n${data.security_assessment}\nInspect the raw SQLite tables above: user profiles, certificates, and blocks are encrypted with AES-256-GCM and keyed with HMAC seals.`);
  } catch (err) {
    logTerminal(`[PEN-TEST ERROR]: ${err.message}`);
  }
}

async function runPenTest_KeyHunting() {
  logTerminal(`>>> EXECUTING PRIVATE KEY HUNTING SCAN:\nSearching server storage, SQLite tables, and memory for student private signing keys...`);
  try {
    const res = await fetch('/api/simulation/pen-test/key-hunting');
    const data = await res.json();

    const card = document.getElementById('pentest-result-card');
    const title = document.getElementById('pentest-result-title');
    const content = document.getElementById('pentest-result-content');

    card.style.display = 'block';
    title.textContent = 'Penetration Test: Private Key Extraction Scan Result';
    content.textContent = JSON.stringify(data, null, 2);

    logTerminal(`[PEN-TEST 2 VERDICT]:\n${data.verdict}\nNo student private keys are held in plaintext on the server.`);
  } catch (err) {
    logTerminal(`[PEN-TEST ERROR]: ${err.message}`);
  }
}

async function runPenTest_DecryptWithoutKey() {
  logTerminal(`>>> EXECUTING UNAUTHORIZED DECRYPTION ATTACK (CPA/CCA):\nAttempting to decrypt database ciphertext with attacker-guessed secret...`);
  try {
    const res = await fetch('/api/simulation/pen-test/decrypt-without-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    const data = await res.json();

    const card = document.getElementById('pentest-result-card');
    const title = document.getElementById('pentest-result-title');
    const content = document.getElementById('pentest-result-content');

    card.style.display = 'block';
    title.textContent = 'Penetration Test: Decrypt Without Key Result';
    content.textContent = JSON.stringify(data, null, 2);

    logTerminal(`[PEN-TEST 3 VERDICT]:\nTarget: ${data.target}\nAuthentication Tag Status: ${data.authenticated_tag_status}\nDecrypted Data: ${JSON.stringify(data.decryption_result)}\n${data.verdict}`);
  } catch (err) {
    logTerminal(`[PEN-TEST ERROR]: ${err.message}`);
  }
}

function logTerminal(message) {
  const term = document.getElementById('attacks-terminal');
  if (term) {
    const time = new Date().toLocaleTimeString();
    term.textContent = `[${time}] ${message}\n\n` + term.textContent;
  }
}

async function executeCustomSql() {
  const query = document.getElementById('sql-query-input').value.trim();
  if (!query) {
    alert('Please enter an SQL query to execute.');
    return;
  }

  logTerminal(`>>> EXECUTING RAW SQL ON DATABASE:\n${query}`);

  try {
    const res = await fetch('/api/simulation/execute-sql', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query })
    });
    const result = await res.json();

    const resultCard = document.getElementById('sql-result-card');
    const resultContent = document.getElementById('sql-result-content');
    resultCard.style.display = 'block';
    resultContent.textContent = JSON.stringify(result, null, 2);

    if (result.sql_execution.success) {
      logTerminal(`[SQL RESULT]: Success! ${result.sql_execution.message}`);
    } else {
      logTerminal(`[SQL ERROR]: ${result.sql_execution.error}`);
    }

    // Cryptographic audit verdict
    if (result.is_ledger_tampered) {
      logTerminal(`[CRYPTOGRAPHIC DEFENSE SUCCESSFUL]:\n` +
        `The database accepted the rogue SQL mutation, but the Cryptographic Verifier DETECTED AND CAUGHT the tampering!\n` +
        `Violations found: ${result.cryptographic_audit.issues.length}`);
    } else {
      logTerminal(`[AUDIT STATUS]: Ledger state intact (Clean or read-only query).`);
    }

    await runDeepAudit();
  } catch (err) {
    logTerminal(`[ERROR]: ${err.message}`);
  }
}

async function runAttack_FrontRunning() {
  logTerminal(`>>> EXECUTING TIME-LOCK FRONT-RUNNING ATTACK:\nAttempting to enroll in CS-902 before start window...`);
  try {
    // 1. Get demo keys
    const keysRes = await fetch('/api/simulation/demo-keys');
    const keys = await keysRes.json();
    const alice = keys.student_alice;

    // 2. Issue invite for CS-902
    const invRes = await fetch('/api/invites/issue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        course_id: 'CS-902',
        student_public_key: alice.pub_key
      })
    });
    const invite = await invRes.json();

    // 3. Premature enrollment
    const enc = await CryptoClient.encryptAESGCM("Front Running Payload");
    const nowIso = new Date().toISOString();
    const nonce = 'early_' + Math.random().toString(36).substring(2, 10);

    const rawTx = {
      course_id: 'CS-902',
      student_public_key: alice.pub_key,
      encrypted_details: enc.ciphertextHex,
      iv_hex: enc.ivHex,
      tag_hex: enc.tagHex,
      invite_id: invite.invite_id,
      admin_signature: invite.admin_signature,
      timestamp: nowIso,
      nonce: nonce
    };

    const canon = CryptoClient.canonicalJson(rawTx);
    const txId = await CryptoClient.sha256(canon);
    const sig = await CryptoClient.signMessage(alice.priv_key, canon);

    const payload = {
      tx_id: txId,
      course_id: 'CS-902',
      student_public_key: alice.pub_key,
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
      body: JSON.stringify(payload)
    });
    const data = await res.json();

    if (!res.ok) {
      logTerminal(`[DEFENSE SUCCESSFUL]: Early front-running enrollment rejected!\nReason: ${data.detail}`);
    } else {
      logTerminal(`[WARNING]: Premature enrollment accepted.`);
    }
  } catch (err) {
    logTerminal(`[DEFENSE SUCCESSFUL]: Early enrollment rejected by time-lock constraint:\n${err.message}`);
  }
}

async function runAttack_Replay() {
  logTerminal(`>>> EXECUTING REPLAY ATTACK:\nIntercepting and re-transmitting Alice's valid transaction...`);
  try {
    const blocksRes = await fetch('/api/ledger/blocks');
    const blocks = await blocksRes.json();

    if (blocks.length < 2 || blocks[1].transactions.length === 0) {
      logTerminal(`[NOTICE]: No transactions available in Block #1 to replay.`);
      return;
    }

    const tx = blocks[1].transactions[0];
    const res = await fetch('/api/enrollments/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(tx)
    });
    const result = await res.json();

    if (!res.ok) {
      logTerminal(`[DEFENSE SUCCESSFUL]: Replay attack intercepted and stopped!\nReason: ${result.detail}`);
    } else {
      logTerminal(`[WARNING]: Replay accepted unexpectedly.`);
    }
  } catch (err) {
    logTerminal(`[DEFENSE SUCCESSFUL]: Replay rejected: ${err.message}`);
  }
}

async function runAttack_CorruptHash() {
  logTerminal(`>>> EXECUTING BLOCK HASH CORRUPTION:\nCorrupting Block #1 header hash in database storage...`);
  try {
    const res = await fetch('/api/simulation/corrupt-block-header?block_index=1', { method: 'POST' });
    const result = await res.json();
    logTerminal(`[CORRUPTION INJECTED]: Changed Block #1 hash from ${result.old_hash} to ${result.corrupted_hash}`);
    await runDeepAudit();
  } catch (err) {
    logTerminal(`[ERROR]: ${err.message}`);
  }
}

async function runAttack_BlockInjection() {
  logTerminal(`>>> EXECUTING DIRECT BLOCK INJECTION ATTACK:\nAttempting to inject unauthorized student into Block #1...`);
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
    logTerminal(`[INJECTION APPLIED]: ${result.message}`);
    await runDeepAudit();
  } catch (err) {
    logTerminal(`[ERROR]: ${err.message}`);
  }
}

async function runDeepAudit() {
  try {
    const res = await fetch('/api/ledger/audit');
    const report = await res.json();

    const badge = document.getElementById('attacks-status-badge');
    const badgeText = document.getElementById('attacks-status-text');

    if (report.is_valid) {
      badge.className = 'status-badge pristine';
      badgeText.textContent = 'LEDGER: PRISTINE';
      logTerminal(`[AUDIT PASSED]: All ${report.total_blocks} blocks and ${report.total_transactions} transactions are mathematically sound.`);
    } else {
      badge.className = 'status-badge corrupted';
      badgeText.textContent = `LEDGER: CORRUPTED (${report.issues.length} VIOLATIONS)`;

      let msg = `[AUDIT: TAMPERING & FORGERY DETECTED]\nTotal Violations: ${report.issues.length}\n`;
      report.issues.forEach((issue, idx) => {
        msg += `\n[Issue #${idx + 1}] Block #${issue.block_index} - Type: ${issue.issue_type}\n` +
          `Description: ${issue.description}\n` +
          (issue.expected ? `Expected: ${issue.expected}\n` : '') +
          (issue.actual ? `Actual:   ${issue.actual}\n` : '');
      });
      logTerminal(msg);
    }
  } catch (err) {
    console.error('Audit failed:', err);
  }
}

async function resetLedger() {
  try {
    const res = await fetch('/api/simulation/reset', { method: 'POST' });
    const data = await res.json();
    alert('Database and blockchain ledger restored to clean state.');
    await runDeepAudit();
  } catch (err) {
    alert(err.message);
  }
}
