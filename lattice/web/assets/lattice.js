(() => {
  const request = async (element, method, url) => {
    const headers = {};
    const token = sessionStorage.getItem("lattice-master-access-token");
    if (token) headers.Authorization = `Bearer ${token}`;
    const response = await fetch(url, {method, headers});
    if (response.status === 401 || response.status === 403) {
      document.dispatchEvent(new CustomEvent("lattice:auth-required"));
      return;
    }
    if (!response.ok) return;
    if (method === "GET") element.outerHTML = await response.text();
    else refreshAll();
  };
  const refreshAll = () => document.querySelectorAll("[hx-get]").forEach((el) => request(el, "GET", el.getAttribute("hx-get")));
  document.addEventListener("click", (event) => {
    const target = event.target.closest("[hx-post]");
    if (!target) return;
    event.preventDefault();
    target.disabled = true;
    request(target, "POST", target.getAttribute("hx-post")).finally(() => { target.disabled = false; });
  });
  document.addEventListener("DOMContentLoaded", () => { refreshAll(); setInterval(refreshAll, 15000); });
  window.latticeRefresh = refreshAll;
})();

(() => {
  const tokenKey = "lattice-master-access-token";
  const token = () => sessionStorage.getItem(tokenKey);

  const showLogin = () => {
    if (!document.querySelector("[data-protected-panel]")) return;
    const target = document.querySelector("[data-protected-panel]");
    target.innerHTML = `<div class="access-note"><p><strong>Connect to your Lattice master</strong></p><p>Enter the master access code created during setup. It stays only in this browser window.</p><input id="master-access-code" type="password" autocomplete="off" placeholder="Master access code"><button id="connect-to-master" type="button">Connect</button></div>`;
    document.getElementById("connect-to-master").addEventListener("click", () => {
      const value = document.getElementById("master-access-code").value.trim();
      if (!value) return;
      sessionStorage.setItem(tokenKey, value);
      window.latticeRefresh();
    });
  };
  document.addEventListener("lattice:auth-required", showLogin);
  document.getElementById("disconnect-dashboard").addEventListener("click", () => {
    sessionStorage.removeItem(tokenKey);
    showLogin();
  });
})();
