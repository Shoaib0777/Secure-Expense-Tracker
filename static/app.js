// Secure Cloud Expense Tracker - JavaScript
// COSC4206 & COSC4607

let authToken = null;
let currentUser = null;
let categoryChart = null;
let currentFilters = {};

// Helpers
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

function showSection(id) {
  $$(".section").forEach(s => s.classList.remove("active"));
  const target = document.getElementById(id);
  if (target) target.classList.add("active");
}

function getAuthHeaders() {
  return authToken ? { "Authorization": `Bearer ${authToken}` } : {};
}

function showError(elementId, message) {
  const el = $(elementId);
  el.textContent = message;
  el.classList.remove("d-none");
}

function hideError(elementId) {
  $(elementId).classList.add("d-none");
}

function showAlert(elementId, message, type = "success") {
  const el = $(elementId);
  el.className = `alert alert-${type}`;
  el.textContent = message;
  el.classList.remove("d-none");
}

// Category colors
const categoryColors = {
  "Food": "#FF6384", "Transport": "#36A2EB", "Rent": "#FFCE56",
  "Groceries": "#4BC0C0", "Shopping": "#9966FF", "Bills": "#FF9F40",
  "Other": "#C9CBCF", "Uncategorized": "#E7E9ED"
};

function getCategoryColor(cat) {
  return categoryColors[cat] || categoryColors["Other"];
}

// ============== Authentication ==============

async function handleLogin(e) {
  e.preventDefault();
  hideError("#login-error");

  const username = $("#login-username").value.trim();
  const password = $("#login-password").value;
  const otpCode = $("#login-otp").value.trim();

  try {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password, otp_code: otpCode })
    });
    const data = await res.json();

    // Step 1: OTP sent to email
    if (data.requires_otp) {
      $("#otp-field").style.display = "block";
      $("#login-error").textContent = data.message || "OTP code sent to your email. Please check your inbox.";
      $("#login-error").classList.remove("alert-danger");
      $("#login-error").classList.add("alert-info");
      $("#login-error").classList.remove("d-none");
      $("#login-otp").focus();
      return;
    }

    if (!data.success) {
      showError("#login-error", data.error || "Login failed");
      return;
    }

    // Success
    authToken = data.token;
    currentUser = data.user;
    localStorage.setItem("authToken", authToken);
    localStorage.setItem("currentUser", JSON.stringify(currentUser));

    updateUIForUser();
    showSection("section-dashboard");
    loadDashboard();

  } catch (err) {
    showError("#login-error", "Connection error");
  }
}

async function handleSignup(e) {
  e.preventDefault();
  hideError("#signup-error");
  $("#signup-success").classList.add("d-none");

  const username = $("#signup-username").value.trim();
  const email = $("#signup-email").value.trim();
  const password = $("#signup-password").value;
  const confirm = $("#signup-confirm").value;

  if (password !== confirm) {
    showError("#signup-error", "Passwords do not match");
    return;
  }

  try {
    const res = await fetch("/api/auth/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, email, password })
    });
    const data = await res.json();

    if (!data.success) {
      showError("#signup-error", data.error || "Signup failed");
      return;
    }

    $("#signup-success").textContent = "Account created! You can now login.";
    $("#signup-success").classList.remove("d-none");
    $("#signup-form").reset();

    setTimeout(() => showSection("section-login"), 2000);

  } catch (err) {
    showError("#signup-error", "Connection error");
  }
}

function handleLogout() {
  authToken = null;
  currentUser = null;
  localStorage.removeItem("authToken");
  localStorage.removeItem("currentUser");
  currentFilters = {};

  $("#nav-username").textContent = "";
  $("#nav-role").textContent = "";
  $("#nav-logout").style.display = "none";
  $("#nav-links").style.display = "none";
  $("#nav-admin-item").style.display = "none";

  showSection("section-login");
}

function updateUIForUser() {
  if (!currentUser) return;

  $("#nav-username").textContent = currentUser.username;
  $("#nav-role").textContent = currentUser.role.toUpperCase();
  $("#nav-logout").style.display = "block";
  $("#nav-links").style.display = "flex";

  // Show admin tab for admin users
  if (currentUser.role === "admin") {
    $("#nav-admin-item").style.display = "block";
  } else {
    $("#nav-admin-item").style.display = "none";
  }

  // Hide add expense for auditors
  if (currentUser.role === "auditor") {
    $("#nav-add-expense").parentElement.style.display = "none";
  } else {
    $("#nav-add-expense").parentElement.style.display = "block";
  }
}

async function verifyStoredToken() {
  const storedToken = localStorage.getItem("authToken");
  const storedUser = localStorage.getItem("currentUser");

  if (!storedToken || !storedUser) return false;

  try {
    const res = await fetch("/api/auth/verify-token", {
      headers: { "Authorization": `Bearer ${storedToken}` }
    });
    const data = await res.json();

    if (data.success) {
      authToken = storedToken;
      currentUser = JSON.parse(storedUser);
      return true;
    }
  } catch (err) {
    console.error("Token verification failed:", err);
  }

  localStorage.removeItem("authToken");
  localStorage.removeItem("currentUser");
  return false;
}

// ============== Dashboard ==============

async function loadDashboard() {
  if (!authToken) return;

  try {
    const res = await fetch("/api/dashboard", { headers: getAuthHeaders() });
    const data = await res.json();

    if (!data.success) {
      console.error(data.error);
      return;
    }

    $("#total-amount").textContent = data.total_amount.toFixed(2);
    $("#total-transactions").textContent = data.total_expenses || 0;
    $("#total-categories").textContent = data.totals_by_category.length;

    // Category table
    const tbody = $("#table-category-body");
    tbody.innerHTML = "";
    if (data.totals_by_category.length === 0) {
      tbody.innerHTML = '<tr><td colspan="2" class="text-muted text-center py-4">No data yet.</td></tr>';
    } else {
      data.totals_by_category.forEach(item => {
        const tr = document.createElement("tr");
        const color = getCategoryColor(item.category);
        tr.innerHTML = `<td><span class="category-dot" style="background-color:${color}"></span>${item.category}</td>
                        <td class="text-end fw-semibold">$${item.amount.toFixed(2)}</td>`;
        tbody.appendChild(tr);
      });
    }

    renderCategoryChart(data.totals_by_category);

  } catch (err) {
    console.error("Dashboard error:", err);
  }
}

function renderCategoryChart(categoryData) {
  const canvas = $("#categoryChart");
  if (!canvas) return;

  const ctx = canvas.getContext("2d");
  if (categoryChart) categoryChart.destroy();

  if (categoryData.length === 0) {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.font = "16px system-ui";
    ctx.fillStyle = "#6c757d";
    ctx.textAlign = "center";
    ctx.fillText("No expense data to display", canvas.width / 2, canvas.height / 2);
    return;
  }

  categoryChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: categoryData.map(i => i.category),
      datasets: [{
        label: "Spending ($)",
        data: categoryData.map(i => i.amount),
        backgroundColor: categoryData.map(i => getCategoryColor(i.category)),
        borderRadius: 8,
        barThickness: 40
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        y: { beginAtZero: true, ticks: { callback: v => "$" + v } },
        x: { grid: { display: false } }
      }
    }
  });
}

// ============== Expenses ==============

function buildFilterQuery() {
  const params = new URLSearchParams();
  if (currentFilters.category) params.append("category", currentFilters.category);
  if (currentFilters.from) params.append("from", currentFilters.from);
  if (currentFilters.to) params.append("to", currentFilters.to);
  if (currentFilters.min_amount) params.append("min_amount", currentFilters.min_amount);
  if (currentFilters.max_amount) params.append("max_amount", currentFilters.max_amount);
  return params.toString();
}

async function loadExpenses() {
  if (!authToken) return;

  try {
    const query = buildFilterQuery();
    const res = await fetch(`/api/expenses?${query}`, { headers: getAuthHeaders() });
    const data = await res.json();

    if (!data.success) {
      console.error(data.error);
      return;
    }

    const tbody = $("#expenses-tbody");
    tbody.innerHTML = "";
    $("#expenses-count").textContent = data.expenses.length;

    let total = 0;
    data.expenses.forEach(e => total += Number(e.amount || 0));
    $("#filter-total").textContent = `(Total: $${total.toFixed(2)})`;

    if (data.expenses.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="text-muted text-center py-4">No expenses found.</td></tr>';
    } else {
      data.expenses.forEach(e => {
        const tr = document.createElement("tr");
        const color = getCategoryColor(e.category || "Other");
        tr.innerHTML = `
          <td class="fw-medium">${e.date || "N/A"}</td>
          <td>${e.vendor || "-"}</td>
          <td><span class="badge" style="background-color:${color}">${e.category || "Uncategorized"}</span></td>
          <td class="text-end fw-semibold">$${Number(e.amount || 0).toFixed(2)}</td>
          <td class="text-muted small">${e.description || "-"}</td>
          <td class="text-center">${e.receipt_url ? `<a href="${e.receipt_url}" target="_blank" class="btn btn-sm btn-outline-primary"><i class="bi bi-image"></i></a>` : '-'}</td>
        `;
        tbody.appendChild(tr);
      });
    }
  } catch (err) {
    console.error("Expenses error:", err);
  }
}

function handleApplyFilters() {
  currentFilters = {
    category: $("#filter-category").value,
    from: $("#filter-from").value,
    to: $("#filter-to").value,
    min_amount: $("#filter-min").value,
    max_amount: $("#filter-max").value
  };
  loadExpenses();
}

function handleClearFilters() {
  currentFilters = {};
  $("#filter-category").value = "";
  $("#filter-from").value = "";
  $("#filter-to").value = "";
  $("#filter-min").value = "";
  $("#filter-max").value = "";
  loadExpenses();
}

function handleExportCsv() {
  if (!authToken) return alert("Please login first");
  const query = buildFilterQuery();
  // Create a link with auth header workaround - open in new tab
  window.open(`/api/export?${query}`, "_blank");
}

// ============== Add Expense ==============

function setupUploadZone() {
  const zone = $("#upload-zone");
  const fileInput = $("#receipt-file");
  const preview = $("#upload-preview");
  const previewImg = $("#preview-img");
  const removeBtn = $("#remove-preview");
  const uploadContent = zone.querySelector(".upload-content");

  zone.addEventListener("click", (e) => {
    if (e.target.closest("#remove-preview")) return;
    fileInput.click();
  });

  zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("drag-over"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("drag-over"));
  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.classList.remove("drag-over");
    if (e.dataTransfer.files.length > 0) {
      fileInput.files = e.dataTransfer.files;
      showPreview(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener("change", () => {
    if (fileInput.files.length > 0) showPreview(fileInput.files[0]);
  });

  removeBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    fileInput.value = "";
    preview.classList.add("d-none");
    uploadContent.classList.remove("d-none");
  });

  function showPreview(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
      previewImg.src = e.target.result;
      preview.classList.remove("d-none");
      uploadContent.classList.add("d-none");
    };
    reader.readAsDataURL(file);
  }
}

async function handleOCR(e) {
  e.preventDefault();
  if (!authToken) return alert("Please login first");

  const fileInput = $("#receipt-file");
  if (!fileInput.files || !fileInput.files.length) {
    showAlert("#ocr-status", "Please select a receipt image first", "warning");
    return;
  }

  const formData = new FormData();
  formData.append("receipt", fileInput.files[0]);

  showAlert("#ocr-status", "Running OCR... Please wait.", "info");

  try {
    const res = await fetch("/api/ocr", {
      method: "POST",
      headers: getAuthHeaders(),
      body: formData
    });
    const data = await res.json();

    if (!data.success) {
      showAlert("#ocr-status", data.error || "OCR failed", "danger");
      return;
    }

    $("#vendor").value = data.vendor || "";
    $("#amount").value = data.amount || "";
    $("#date").value = data.date || "";
    $("#ocr-raw-text").textContent = data.raw_text || "";
    $("#hidden-ocr-raw-text").value = data.raw_text || "";

    if (data.category) $("#category").value = data.category;

    showAlert("#ocr-status", `OCR completed!${data.category ? ` Category: ${data.category}` : ""}`, "success");

  } catch (err) {
    showAlert("#ocr-status", "OCR error", "danger");
  }
}

async function handleSaveExpense(e) {
  e.preventDefault();
  if (!authToken) return alert("Please login first");

  const amount = $("#amount").value.trim();
  if (!amount) {
    showAlert("#save-status", "Amount is required", "warning");
    return;
  }

  const formData = new FormData();
  formData.append("vendor", $("#vendor").value.trim());
  formData.append("amount", amount);
  formData.append("date", $("#date").value.trim());
  formData.append("category", $("#category").value);
  formData.append("description", $("#description").value.trim());
  formData.append("ocr_raw_text", $("#hidden-ocr-raw-text").value);

  const fileInput = $("#receipt-file");
  if (fileInput.files && fileInput.files.length > 0) {
    formData.append("receipt", fileInput.files[0]);
  }

  showAlert("#save-status", "Saving expense...", "info");

  try {
    const res = await fetch("/api/expenses", {
      method: "POST",
      headers: getAuthHeaders(),
      body: formData
    });
    const data = await res.json();

    if (!data.success) {
      showAlert("#save-status", data.error || "Save failed", "danger");
      return;
    }

    showAlert("#save-status", "Expense saved securely!", "success");
    $("#add-expense-form").reset();
    $("#ocr-raw-text").textContent = "Run OCR to see extracted text.";
    $("#upload-preview").classList.add("d-none");
    $("#upload-zone .upload-content").classList.remove("d-none");
    $("#ocr-status").classList.add("d-none");

    loadDashboard();

  } catch (err) {
    showAlert("#save-status", "Save error", "danger");
  }
}

// ============== Security Settings ==============

async function loadSecuritySettings() {
  // Email OTP is always enabled, no setup required
  // This function is kept for compatibility but does nothing
  console.log("Email OTP is enabled by default");
}

// ============== Admin Panel ==============

async function loadAdminPanel() {
  if (!authToken || currentUser?.role !== "admin") return;

  // Load users
  try {
    const res = await fetch("/api/admin/users", { headers: getAuthHeaders() });
    const data = await res.json();

    const tbody = $("#admin-users-tbody");
    tbody.innerHTML = "";

    if (data.success && data.users.length > 0) {
      data.users.forEach(u => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${u.username}</td>
          <td>${u.email}</td>
          <td>
            <select class="form-select form-select-sm" data-userid="${u.id}" onchange="updateUserRole(this)">
              <option value="user" ${u.role === "user" ? "selected" : ""}>User</option>
              <option value="auditor" ${u.role === "auditor" ? "selected" : ""}>Auditor</option>
              <option value="admin" ${u.role === "admin" ? "selected" : ""}>Admin</option>
            </select>
          </td>
          <td>${u.otp_enabled ? '<span class="badge bg-success">Enabled</span>' : '<span class="badge bg-secondary">Disabled</span>'}</td>
          <td>${u.is_active ? '<span class="badge bg-success">Active</span>' : '<span class="badge bg-danger">Disabled</span>'}</td>
          <td>
            <button class="btn btn-sm ${u.is_active ? 'btn-warning' : 'btn-success'}" onclick="toggleUserStatus('${u.id}', ${!u.is_active})">
              ${u.is_active ? 'Disable' : 'Enable'}
            </button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    }
  } catch (err) {
    console.error("Admin users error:", err);
  }

  // Load security logs
  try {
    const res = await fetch("/api/admin/security-logs", { headers: getAuthHeaders() });
    const data = await res.json();

    const tbody = $("#admin-logs-tbody");
    tbody.innerHTML = "";

    if (data.success && data.logs.length > 0) {
      data.logs.forEach(log => {
        const tr = document.createElement("tr");
        const timestamp = log.timestamp ? new Date(log.timestamp._seconds * 1000).toLocaleString() : "N/A";
        tr.innerHTML = `
          <td class="small">${timestamp}</td>
          <td><span class="badge bg-info">${log.event_type}</span></td>
          <td class="small">${log.user_id || "-"}</td>
          <td class="small">${log.ip_address || "-"}</td>
          <td class="small">${JSON.stringify(log.details || {})}</td>
        `;
        tbody.appendChild(tr);
      });
    }
  } catch (err) {
    console.error("Admin logs error:", err);
  }
}

async function updateUserRole(select) {
  const userId = select.dataset.userid;
  const newRole = select.value;

  try {
    const res = await fetch(`/api/admin/users/${userId}/role`, {
      method: "PUT",
      headers: { ...getAuthHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ role: newRole })
    });
    const data = await res.json();
    if (data.success) alert("Role updated!");
  } catch (err) {
    alert("Error updating role");
  }
}

async function toggleUserStatus(userId, isActive) {
  try {
    const res = await fetch(`/api/admin/users/${userId}/status`, {
      method: "PUT",
      headers: { ...getAuthHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ is_active: isActive })
    });
    const data = await res.json();
    if (data.success) {
      alert(`Account ${isActive ? 'enabled' : 'disabled'}!`);
      loadAdminPanel();
    }
  } catch (err) {
    alert("Error updating status");
  }
}

// ============== Navigation ==============

function setupNav() {
  $("#nav-dashboard").addEventListener("click", (e) => {
    e.preventDefault();
    showSection("section-dashboard");
    loadDashboard();
  });

  $("#nav-expenses").addEventListener("click", (e) => {
    e.preventDefault();
    showSection("section-expenses");
    loadExpenses();
  });

  $("#nav-add-expense").addEventListener("click", (e) => {
    e.preventDefault();
    showSection("section-add-expense");
    $("#date").value = new Date().toISOString().split("T")[0];
  });

  $("#nav-security").addEventListener("click", (e) => {
    e.preventDefault();
    showSection("section-security");
    loadSecuritySettings();
  });

  $("#nav-admin").addEventListener("click", (e) => {
    e.preventDefault();
    showSection("section-admin");
    loadAdminPanel();
  });

  $("#nav-logout").addEventListener("click", (e) => {
    e.preventDefault();
    handleLogout();
  });

  $("#show-signup").addEventListener("click", (e) => {
    e.preventDefault();
    showSection("section-signup");
  });

  $("#show-login").addEventListener("click", (e) => {
    e.preventDefault();
    showSection("section-login");
  });
}

// ============== Init ==============

async function init() {
  // Check stored token
  const isValid = await verifyStoredToken();

  if (isValid) {
    updateUIForUser();
    showSection("section-dashboard");
    loadDashboard();
  } else {
    showSection("section-login");
  }

  // Auth forms
  $("#login-form").addEventListener("submit", handleLogin);
  $("#signup-form").addEventListener("submit", handleSignup);

  // Add expense
  $("#ocr-button").addEventListener("click", handleOCR);
  $("#save-expense-button").addEventListener("click", handleSaveExpense);

  // Filters
  $("#apply-filters-btn").addEventListener("click", handleApplyFilters);
  $("#clear-filters-btn").addEventListener("click", handleClearFilters);
  $("#export-csv-btn").addEventListener("click", handleExportCsv);

  // Setup
  setupUploadZone();
  setupNav();
}

document.addEventListener("DOMContentLoaded", init);

// Global functions for inline handlers
window.updateUserRole = updateUserRole;
window.toggleUserStatus = toggleUserStatus;
