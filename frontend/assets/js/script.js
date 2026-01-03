// ================================
// GLOBAL CONFIG
// ================================
const API_BASE_URL = "http://localhost:5000";

// ================================
// AUTH HELPERS
// ================================
function getToken() {
  return localStorage.getItem("token");
}

function getAuthHeaders() {
  return {
    "Content-Type": "application/json",
    "Authorization": `Bearer ${getToken()}`
  };
}

function checkAuth() {
  const path = window.location.pathname;
  if (
    !getToken() &&
    !path.includes("index.html") &&
    !path.includes("signup.html")
  ) {
    window.location.href = "index.html";
  }
}

function logout() {
  localStorage.removeItem("token");
  localStorage.removeItem("user");
  window.location.href = "index.html";
}

// ================================
// GENERIC FETCH HELPER
// ================================
async function apiFetch(url, options = {}) {
  const response = await fetch(`${API_BASE_URL}${url}`, options);

  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error("Server not responding");
  }

  if (!response.ok) {
    throw new Error(data.error || "API error");
  }

  return data;
}

// ================================
// GLOBAL ERROR HANDLER
// ================================
window.addEventListener("unhandledrejection", event => {
  alert(event.reason?.message || "Unexpected error");
});
