// Portal Client State (Stored in sessionStorage for isolated multi-tab testing)
const PortalState = {
  user: null,
  courses: [],
  studentRequests: [],
  instructorRequests: []
};

document.addEventListener('DOMContentLoaded', async () => {
  const savedUser = sessionStorage.getItem('crypto_user');
  if (savedUser) {
    try {
      PortalState.user = JSON.parse(savedUser);
    } catch (e) {
      sessionStorage.removeItem('crypto_user');
    }
  }

  const urlParams = new URLSearchParams(window.location.search);
  const codeParam = urlParams.get('code');
  if (codeParam) {
    const input = document.getElementById('join-course-code');
    if (input) input.value = codeParam;
  }

  renderNavigation();
  updateViews();
});

// =====================================================================
// AUTHENTICATION & SESSION MANAGEMENT
// =====================================================================

function renderNavigation() {
  const userSec = document.getElementById('nav-user-section');
  if (!userSec) return;

  if (PortalState.user) {
    userSec.innerHTML = `
      <div style="font-size: 0.85rem; text-align: right;">
        <div style="font-weight: 700; color: #fff;">${PortalState.user.name}</div>
        <div style="color: var(--accent-cyan); font-size: 0.75rem; text-transform: uppercase;">
          ${PortalState.user.role} (${PortalState.user.email})
        </div>
      </div>
      <button class="btn btn-secondary btn-sm" onclick="logout()">Sign Out</button>
    `;
  } else {
    userSec.innerHTML = `
      <button class="btn btn-primary btn-sm" onclick="showAuthModal()">Sign In / Register</button>
    `;
  }
}

function updateViews() {
  const authView = document.getElementById('auth-view');
  const studentView = document.getElementById('student-view');
  const instructorView = document.getElementById('instructor-view');

  authView.style.display = 'none';
  studentView.style.display = 'none';
  instructorView.style.display = 'none';

  if (!PortalState.user) {
    authView.style.display = 'block';
  } else if (PortalState.user.role === 'student') {
    studentView.style.display = 'block';
    const welcome = document.getElementById('student-welcome-text');
    if (welcome) welcome.textContent = `Welcome, ${PortalState.user.name}`;
    loadStudentCourses();
    loadStudentApplications();
  } else if (PortalState.user.role === 'instructor') {
    instructorView.style.display = 'block';
    const welcome = document.getElementById('instructor-welcome-text');
    if (welcome) welcome.textContent = `Welcome, ${PortalState.user.name}`;
    loadInstructorCourses();
    loadInstructorRequests();
  }
}

let isRegisterMode = false;
function toggleAuthMode() {
  isRegisterMode = !isRegisterMode;
  document.getElementById('auth-title').textContent = isRegisterMode ? 'Create New Account' : 'Sign In to Your Account';
  document.getElementById('auth-submit-btn').textContent = isRegisterMode ? 'Register Account' : 'Sign In';
  document.getElementById('auth-toggle-btn').textContent = isRegisterMode ? 'Sign In Instead' : 'Create Account';
  document.getElementById('name-group').style.display = isRegisterMode ? 'block' : 'none';
  document.getElementById('role-group').style.display = isRegisterMode ? 'block' : 'none';
}

async function handleAuthSubmit(event) {
  event.preventDefault();
  const email = document.getElementById('auth-email').value;
  const password = document.getElementById('auth-password').value;

  try {
    if (isRegisterMode) {
      const name = document.getElementById('auth-name').value;
      const role = document.getElementById('auth-role').value;
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, name, role })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Registration failed');
      saveUserSession(data.profile, data.private_key);
    } else {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Login failed');
      saveUserSession(data.profile, data.private_key);
    }
  } catch (err) {
    alert(err.message);
  }
}

async function quickLogin(email, password) {
  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Quick login failed');
    saveUserSession(data.profile, data.private_key);
  } catch (err) {
    alert('Quick login error: ' + (err.message || err.detail));
  }
}

function saveUserSession(profile, privateKey) {
  PortalState.user = {
    ...profile,
    private_key: privateKey
  };
  sessionStorage.setItem('crypto_user', JSON.stringify(PortalState.user));
  renderNavigation();
  updateViews();
}

function logout() {
  sessionStorage.removeItem('crypto_user');
  PortalState.user = null;
  renderNavigation();
  updateViews();
}

// =====================================================================
// STUDENT WORKFLOWS
// =====================================================================

async function loadStudentCourses() {
  try {
    const res = await fetch('/api/courses');
    const courses = await res.json();
    PortalState.courses = courses;

    const container = document.getElementById('student-available-courses');
    if (!container) return;

    if (courses.length === 0) {
      container.innerHTML = `<div style="color: var(--text-muted); font-size: 0.85rem;">No courses available.</div>`;
      return;
    }

    container.innerHTML = courses.map(c => `
      <div style="background: rgba(255,255,255,0.03); padding: 0.75rem 1rem; border-radius: var(--radius-sm); border: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center;">
        <div>
          <div style="font-weight: 700; color: #fff;">${c.course_code}: ${c.title}</div>
          <div style="font-size: 0.8rem; color: var(--text-muted);">
            👨‍🏫 ${c.instructor_name} • 👥 Seats: ${c.enrolled_count}/${c.capacity}
          </div>
        </div>
        <button class="btn btn-secondary btn-sm" onclick="selectCourseCode('${c.course_code}')">Select</button>
      </div>
    `).join('');
  } catch (err) {
    console.error('Error fetching courses:', err);
  }
}

function selectCourseCode(code) {
  const input = document.getElementById('join-course-code');
  if (input) {
    input.value = code;
    input.scrollIntoView({ behavior: 'smooth' });
  }
}

async function handleJoinCourse(event) {
  event.preventDefault();
  const code = document.getElementById('join-course-code').value.trim();
  const statusDiv = document.getElementById('join-status-msg');

  try {
    const res = await fetch(`/api/courses/code/${code}`);
    if (!res.ok) throw new Error(`Course with code '${code}' not found.`);
    const course = await res.json();

    const reqRes = await fetch('/api/invites/request', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        course_id: course.course_id,
        student_name: PortalState.user.name,
        student_email: PortalState.user.email,
        student_public_key: PortalState.user.public_key
      })
    });
    const reqData = await reqRes.json();
    if (!reqRes.ok) throw new Error(reqData.detail || 'Failed to submit request');

    statusDiv.innerHTML = `<span style="color: var(--accent-emerald);">✓ Request sent to ${course.instructor_name}. Waiting for approval!</span>`;
    document.getElementById('join-course-code').value = '';
    await loadStudentApplications();
  } catch (err) {
    statusDiv.innerHTML = `<span style="color: var(--accent-crimson);">${err.message || err.detail}</span>`;
  }
}

async function loadStudentApplications() {
  if (!PortalState.user) return;
  try {
    const res = await fetch(`/api/invites/requests/student/${PortalState.user.email}`);
    const requests = await res.json();
    PortalState.studentRequests = requests;

    const tbody = document.getElementById('student-applications-tbody');
    if (!tbody) return;

    if (requests.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No applications yet. Enter a course code above to join!</td></tr>`;
      return;
    }

    const coursesRes = await fetch('/api/courses');
    const courses = await coursesRes.json();
    const coursesMap = {};
    courses.forEach(c => {
      coursesMap[c.course_id.toUpperCase()] = c;
      coursesMap[c.course_code.toUpperCase()] = c;
    });

    const blocksRes = await fetch('/api/ledger/blocks');
    const blocks = await blocksRes.json();
    const enrolledCourses = new Set();
    blocks.forEach(b => {
      b.transactions.forEach(t => {
        if (t.student_public_key.toLowerCase() === PortalState.user.public_key.toLowerCase()) {
          enrolledCourses.add(t.course_id.toUpperCase());
        }
      });
    });

    tbody.innerHTML = requests.map(req => {
      const course = coursesMap[req.course_id.toUpperCase()] || { course_code: req.course_id, title: '', instructor_name: '', is_enrollment_open: false, is_timed: false };
      const isEnrolled = enrolledCourses.has(req.course_id.toUpperCase());

      let statusBadge = '';
      let actionBtn = '';

      if (isEnrolled) {
        statusBadge = `<span class="badge badge-green">🎉 Enrolled in Course</span>`;
        actionBtn = `<span style="color: var(--accent-emerald); font-size: 0.8rem;">✓ Seat Confirmed</span>`;
      } else if (req.status === 'APPROVED') {
        const canEnroll = course.is_enrollment_open;
        if (canEnroll) {
          statusBadge = `<span class="badge badge-green">✓ Validated by Instructor</span>`;
          actionBtn = `<button class="btn btn-primary btn-sm" onclick="completeEnrollment('${req.course_id}', '${req.invite_id || ''}')">✍️ Complete Enrollment</button>`;
        } else {
          statusBadge = `<span class="badge badge-yellow">✓ Validated (Awaiting Enrollment Start)</span>`;
          actionBtn = `<span style="color: var(--text-muted); font-size: 0.8rem;">⏳ Enrollment Not Started</span>`;
        }
      } else if (req.status === 'REJECTED') {
        statusBadge = `<span class="badge badge-red">Application Rejected</span>`;
        actionBtn = `-`;
      } else {
        statusBadge = `<span class="badge badge-yellow">⏳ Pending Instructor Review</span>`;
        actionBtn = `<span style="color: var(--text-muted); font-size: 0.8rem;">Awaiting Review</span>`;
      }

      return `
        <tr>
          <td>
            <strong>${course.course_code}</strong><br>
            <span style="font-size: 0.78rem; color: var(--text-muted);">${course.title}</span>
          </td>
          <td>${course.instructor_name}</td>
          <td>${course.is_timed ? 'Timed Schedule' : 'Untimed / Manual Start'}</td>
          <td>${statusBadge}</td>
          <td>${actionBtn}</td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    console.error('Error loading applications:', err);
  }
}

// Complete Enrollment with robust certificate lookup and signature
async function completeEnrollment(courseId, inviteId) {
  try {
    // 1. Fetch certificate
    let invite = null;
    if (inviteId) {
      try {
        const invRes = await fetch(`/api/invites/certificate/${inviteId}`);
        if (invRes.ok) {
          invite = await invRes.json();
        }
      } catch (e) {}
    }

    if (!invite) {
      const invitesRes = await fetch(`/api/invites/student/${PortalState.user.public_key}`);
      const invites = await invitesRes.json();
      invite = invites.find(inv => 
        (inviteId && inv.invite_id === inviteId) ||
        inv.course_id.toUpperCase() === courseId.toUpperCase()
      );
    }

    if (!invite) {
      throw new Error(`Invitation certificate not found for '${courseId}'. Ensure instructor has approved your request.`);
    }

    // 2. Encrypt student confidential payload
    const confidentialData = `Student: ${PortalState.user.name} • Email: ${PortalState.user.email} • Verified Enrollment`;
    const enc = await CryptoClient.encryptAESGCM(confidentialData);

    // 3. Prepare transaction and sign digitally
    const nowIso = new Date().toISOString();
    const nonce = 'tx_' + Math.random().toString(36).substring(2, 12);

    const rawTxDict = {
      course_id: invite.course_id,
      student_public_key: PortalState.user.public_key,
      encrypted_details: enc.ciphertextHex,
      iv_hex: enc.ivHex,
      tag_hex: enc.tagHex,
      invite_id: invite.invite_id,
      admin_signature: invite.admin_signature,
      timestamp: nowIso,
      nonce: nonce
    };

    const canonicalTx = CryptoClient.canonicalJson(rawTxDict);
    const txId = await CryptoClient.sha256(canonicalTx);
    const studentSig = await CryptoClient.signMessage(
      PortalState.user.private_key, 
      canonicalTx, 
      PortalState.user.public_key
    );

    const txPayload = {
      tx_id: txId,
      course_id: invite.course_id,
      student_public_key: PortalState.user.public_key,
      encrypted_details: enc.ciphertextHex,
      iv_hex: enc.ivHex,
      tag_hex: enc.tagHex,
      invite_certificate: invite,
      timestamp: nowIso,
      nonce: nonce,
      student_signature: studentSig
    };

    // 4. Submit to blockchain ledger
    const res = await fetch('/api/enrollments/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(txPayload)
    });
    const result = await res.json();
    if (!res.ok) {
      throw new Error(result.detail || 'Enrollment rejected by blockchain ledger');
    }

    alert(`🎉 Enrollment Successful! Verified and committed into Block #${result.receipt?.block_index || 'new'}.`);
    await loadStudentApplications();
  } catch (err) {
    const errorMsg = err.message || err.detail || (typeof err === 'object' ? JSON.stringify(err) : String(err));
    alert('Enrollment error: ' + errorMsg);
    console.error('Full enrollment error:', err);
  }
}

// =====================================================================
// INSTRUCTOR WORKFLOWS
// =====================================================================

function toggleScheduleInputs() {
  const mode = document.getElementById('course-mode-select').value;
  const row = document.getElementById('timed-inputs-row');
  row.style.display = (mode === 'timed') ? 'grid' : 'none';
}

async function handleCreateCourse(event) {
  event.preventDefault();
  const code = document.getElementById('course-code-input').value.trim();
  const title = document.getElementById('course-title-input').value.trim();
  const capacity = parseInt(document.getElementById('course-capacity-input').value);
  const desc = document.getElementById('course-desc-input').value.trim();
  const mode = document.getElementById('course-mode-select').value;

  let isTimed = (mode === 'timed');
  let start = null;
  let end = null;
  if (isTimed) {
    const sVal = document.getElementById('course-start-input').value;
    const eVal = document.getElementById('course-end-input').value;
    if (!sVal || !eVal) {
      alert('Please specify enrollment start and end schedules for timed courses.');
      return;
    }
    start = new Date(sVal).toISOString();
    end = new Date(eVal).toISOString();
  }

  const payload = {
    course_code: code,
    title: title,
    description: desc,
    instructor_name: PortalState.user.name,
    instructor_email: PortalState.user.email,
    instructor_public_key: PortalState.user.public_key,
    capacity: capacity,
    is_timed: isTimed,
    schedule_start: start,
    schedule_end: end
  };

  try {
    const res = await fetch('/api/courses', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Failed to create course');

    alert(`Course '${data.course_code}' created! Students can join using code: ${data.course_code}`);
    document.getElementById('course-code-input').value = '';
    document.getElementById('course-title-input').value = '';
    document.getElementById('course-desc-input').value = '';
    await loadInstructorCourses();
  } catch (err) {
    alert(err.message || err.detail);
  }
}

async function loadInstructorCourses() {
  if (!PortalState.user) return;
  try {
    const res = await fetch('/api/courses');
    const allCourses = await res.json();
    const myCourses = allCourses.filter(c => c.instructor_email.toLowerCase() === PortalState.user.email.toLowerCase());

    const container = document.getElementById('instructor-courses-list');
    if (!container) return;

    if (myCourses.length === 0) {
      container.innerHTML = `<div style="color: var(--text-muted); font-size: 0.85rem;">You haven't created any courses yet.</div>`;
      return;
    }

    container.innerHTML = myCourses.map(c => `
      <div class="card" style="margin-bottom: 0;">
        <div class="card-header">
          <div>
            <span class="badge badge-cyan">${c.course_code}</span>
            <div style="font-weight: 700; font-size: 1.05rem; margin-top: 0.3rem;">${c.title}</div>
          </div>
          <span class="badge ${c.status === 'OPEN' ? 'badge-green' : 'badge-yellow'}">${c.status}</span>
        </div>

        <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.75rem;">${c.description || 'No description'}</p>

        <div style="font-size: 0.82rem; margin-bottom: 0.75rem;">
          <div>👥 <strong>Enrolled:</strong> ${c.enrolled_count} / ${c.capacity}</div>
          <div>🔗 <strong>Registration Code:</strong> <code>${c.course_code}</code></div>
          <div>🌐 <strong>Direct Link:</strong> <a href="/?code=${c.course_code}" target="_blank" style="color: var(--accent-cyan);">/?code=${c.course_code}</a></div>
        </div>

        <div style="border-top: 1px solid var(--border-color); padding-top: 0.75rem; display: flex; justify-content: space-between; align-items: center;">
          <span style="font-size: 0.8rem; color: var(--text-muted);">
            Mode: ${c.is_timed ? 'Timed Schedule' : 'Manual Start/Stop'}
          </span>
          ${!c.is_timed ? `
            <button class="btn btn-sm ${c.is_enrollment_open ? 'btn-danger' : 'btn-success'}" onclick="toggleEnrollmentState('${c.course_id}')">
              ${c.is_enrollment_open ? '⏹ Stop Enrollment' : '▶ Start Enrollment'}
            </button>
          ` : ''}
        </div>
      </div>
    `).join('');
  } catch (err) {
    console.error('Error loading instructor courses:', err);
  }
}

async function toggleEnrollmentState(courseId) {
  try {
    const res = await fetch(`/api/courses/${courseId}/toggle-enrollment`, { method: 'POST' });
    const data = await res.json();
    alert(`Enrollment is now: ${data.status}`);
    await loadInstructorCourses();
  } catch (err) {
    alert(err.message || err.detail);
  }
}

async function loadInstructorRequests() {
  if (!PortalState.user) return;
  try {
    const coursesRes = await fetch('/api/courses');
    const allCourses = await coursesRes.json();
    const myCourses = allCourses.filter(c => c.instructor_email.toLowerCase() === PortalState.user.email.toLowerCase());

    const tbody = document.getElementById('instructor-requests-tbody');
    if (!tbody) return;

    let allRequests = [];
    for (const c of myCourses) {
      const reqRes = await fetch(`/api/invites/requests/course/${c.course_id}`);
      const reqs = await reqRes.json();
      allRequests = allRequests.concat(reqs);
    }

    if (allRequests.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No student validation requests yet.</td></tr>`;
      return;
    }

    tbody.innerHTML = allRequests.map(r => `
      <tr>
        <td><strong>${r.student_name}</strong></td>
        <td>${r.student_email}</td>
        <td><span class="badge badge-cyan">${r.course_id}</span></td>
        <td style="font-size: 0.8rem; color: var(--text-muted);">${new Date(r.created_at).toLocaleTimeString()}</td>
        <td>
          <span class="badge ${r.status === 'APPROVED' ? 'badge-green' : (r.status === 'REJECTED' ? 'badge-red' : 'badge-yellow')}">
            ${r.status}
          </span>
        </td>
        <td>
          ${r.status === 'PENDING' ? `
            <div style="display: flex; gap: 0.4rem;">
              <button class="btn btn-sm btn-success" onclick="approveRequest('${r.request_id}')">✓ Approve</button>
              <button class="btn btn-sm btn-danger" onclick="rejectRequest('${r.request_id}')">✕ Reject</button>
            </div>
          ` : `
            <span style="font-size: 0.8rem; color: var(--text-muted);">Processed</span>
          `}
        </td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Error loading instructor requests:', err);
  }
}

async function approveRequest(requestId) {
  try {
    const res = await fetch('/api/invites/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        request_id: requestId,
        instructor_private_key: PortalState.user.private_key
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Failed to approve');
    alert('Student approved and cryptographic invitation certificate signed!');
    await loadInstructorRequests();
  } catch (err) {
    alert(err.message || err.detail);
  }
}

async function rejectRequest(requestId) {
  try {
    const res = await fetch('/api/invites/reject', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ request_id: requestId })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Failed to reject');
    await loadInstructorRequests();
  } catch (err) {
    alert(err.message || err.detail);
  }
}
