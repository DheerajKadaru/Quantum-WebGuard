document.addEventListener("DOMContentLoaded", () => {
  const page = document.body.getAttribute("data-page") || "home";

  // ========================
  // Navigation
  // ========================

  const topNav = document.getElementById("topNav");
  const navToggle = document.getElementById("navToggle");
  const navLinks = document.getElementById("navLinks");

  const setNavScrollState = () => {
    if (topNav) {
      topNav.classList.toggle("scrolled", window.scrollY > 20);
    }
  };

  if (navToggle && navLinks) {
    navToggle.addEventListener("click", () => {
      const isOpen = navLinks.classList.toggle("open");
      navToggle.setAttribute("aria-expanded", String(isOpen));
    });
  }

  window.addEventListener("scroll", setNavScrollState);
  setNavScrollState();

  // ========================
  // Reveal on scroll
  // ========================

  const revealNodes = document.querySelectorAll(".reveal");
  if (revealNodes.length) {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add("visible");
          }
        });
      },
      { threshold: 0.1 }
    );
    revealNodes.forEach((node) => observer.observe(node));
  }

  // ========================
  // Chart.js defaults
  // ========================

  if (typeof Chart !== "undefined") {
    Chart.defaults.color = "#94a3b8";
    Chart.defaults.font.family = "'Inter', sans-serif";
  }

  // ========================
  // ANALYZE page logic
  // ========================

  if (page === "analyze") {
    const form = document.getElementById("scan-form");
    const urlInput = document.getElementById("url-input");
    const scanBtn = document.getElementById("scanBtn");
    const btnText = scanBtn?.querySelector(".btn-text");
    const btnLoading = scanBtn?.querySelector(".btn-loading");
    const errorBox = document.getElementById("analysisError");
    const resultPanel = document.getElementById("analysisResult");
    const predictionBadge = document.getElementById("predictionBadge");
    const confidenceChartCtx = document.getElementById("confidenceChart");
    const confidenceCenterText = document.getElementById("confidenceCenterText");
    const attackType = document.getElementById("attackType");
    const riskScore = document.getElementById("riskScore");
    const resultTimestamp = document.getElementById("resultTimestamp");
    const resultDescription = document.getElementById("resultDescription");
    const analysisSource = document.getElementById("analysisSource");
    const analysisReasoning = document.getElementById("analysisReasoning");

    let confidenceChartInst = null;

    // Init confidence chart
    if (confidenceChartCtx && typeof Chart !== "undefined") {
      confidenceChartInst = new Chart(confidenceChartCtx, {
        type: "doughnut",
        data: {
          labels: ["Confidence", ""],
          datasets: [{
            data: [0, 100],
            backgroundColor: ["#38bdf8", "rgba(15,23,42,0.4)"],
            borderWidth: 0,
            cutout: "80%",
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false }, tooltip: { enabled: false } },
          animation: { animateScale: true, animateRotate: true },
        },
      });
    }

    const parseConfidence = (value) => {
      if (typeof value === "number") return Math.max(0, Math.min(100, value));
      if (typeof value === "string") {
        const num = parseFloat(value.replace("%", ""));
        if (!isNaN(num)) return Math.max(0, Math.min(100, num));
      }
      return 0;
    };

    const showError = (msg) => {
      if (errorBox) {
        errorBox.textContent = msg;
        errorBox.hidden = false;
      }
      if (resultPanel) resultPanel.hidden = true;
    };

    const setLoading = (loading) => {
      if (btnText) btnText.style.display = loading ? "none" : "";
      if (btnLoading) btnLoading.classList.toggle("active", loading);
      if (scanBtn) scanBtn.disabled = loading;
    };

    if (form && urlInput) {
      form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const rawUrl = urlInput.value.trim();
        if (!rawUrl) { showError("Please enter a valid URL."); return; }

        if (errorBox) errorBox.hidden = true;
        setLoading(true);

        try {
          const response = await fetch("/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: rawUrl }),
          });

          const data = await response.json().catch(() => ({}));
          if (!response.ok) {
            showError(data.error || data.message || "Analysis failed.");
            return;
          }

          const prediction = data.prediction || data.final_prediction || "Unknown";
          const confidenceValue = parseConfidence(data.confidence_value ?? data.confidence);
          const attack = data.attack_type || "None";
          const risk = typeof data.risk_score === "number"
            ? data.risk_score.toFixed(2)
            : parseFloat(data.risk_score || "0").toFixed(2);
          const isSafe = prediction === "Safe";
          const isWarning = prediction.startsWith("Likely");

          if (resultPanel) resultPanel.hidden = false;

          if (predictionBadge) {
            predictionBadge.textContent = prediction;
            predictionBadge.classList.remove("safe", "malicious", "warning");
            if (isWarning) predictionBadge.classList.add("warning");
            else predictionBadge.classList.add(isSafe ? "safe" : "malicious");
          }

          if (confidenceChartInst) {
            confidenceChartInst.data.datasets[0].data = [confidenceValue, 100 - confidenceValue];
            if (isWarning) confidenceChartInst.data.datasets[0].backgroundColor[0] = "#f59e0b"; // Amber
            else confidenceChartInst.data.datasets[0].backgroundColor[0] = isSafe ? "#22c55e" : "#ef4444";
            confidenceChartInst.update();
          }

          if (confidenceCenterText) {
            confidenceCenterText.textContent = `${confidenceValue.toFixed(0)}%`;
            if (isWarning) confidenceCenterText.style.color = "#fcd34d";
            else confidenceCenterText.style.color = isSafe ? "#86efac" : "#fca5a5";
          }

          if (attackType) {
            attackType.textContent = attack;
            let statusClass = "malicious";
            if (isSafe) statusClass = "safe";
            else if (isWarning) statusClass = "warning";
            attackType.className = "metric-value attack-badge " + statusClass;
          }

          if (riskScore) riskScore.textContent = risk;

          if (resultDescription) {
            resultDescription.textContent = isSafe
              ? "No significant threat signatures or high-confidence malicious patterns were detected by our primary systems."
              : `Warning! High-risk signal detected. Characterized primarily as ${attack}. Exercise caution.`;
          }

          if (analysisSource) {
            analysisSource.textContent = data.source || "SVC";
            analysisSource.className = "metric-value source-badge " + (data.source ? data.source.toLowerCase().replace(" ", "-") : "svc");
          }

          if (analysisReasoning) {
            analysisReasoning.textContent = data.reasoning || "No detailed technical breakdown available.";
          }

          if (resultTimestamp) {
            resultTimestamp.textContent = data.timestamp || new Date().toISOString().slice(0, 19).replace("T", " ");
          }
        } catch (err) {
          showError(err.message || "Could not analyze this URL.");
        } finally {
          setLoading(false);
        }
      });
    }
  }

  // ========================
  // RESULTS page logic
  // ========================

  if (page === "results") {
    const historyChartCtx = document.getElementById("historyChart");
    const totalEl = document.getElementById("totalScansValue");
    const maliciousEl = document.getElementById("maliciousCountValue");
    const safeEl = document.getElementById("safeCountValue");

    if (historyChartCtx && typeof Chart !== "undefined") {
      const total = parseInt(totalEl?.textContent || "0");
      const malicious = parseInt(maliciousEl?.textContent || "0");
      const safe = parseInt(safeEl?.textContent || "0") || Math.max(0, total - malicious);

      new Chart(historyChartCtx, {
        type: "doughnut",
        data: {
          labels: ["Safe", "Malicious"],
          datasets: [{
            data: [safe, malicious],
            backgroundColor: ["#22c55e", "#ef4444"],
            borderWidth: 2,
            borderColor: "#0f172a",
            hoverBorderColor: "#1e293b",
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: "bottom",
              labels: {
                color: "#f1f5f9",
                padding: 20,
                usePointStyle: true,
                pointStyle: "circle",
                font: { size: 13, weight: 500 },
              },
            },
          },
          cutout: "65%",
        },
      });
    }
  }

  // ========================
  // Counter animation (home stats)
  // ========================

  if (page === "home") {
    const counters = document.querySelectorAll("[data-count]");
    const animateCounter = (el) => {
      const target = parseInt(el.getAttribute("data-count"));
      if (isNaN(target) || target === 0) return;
      const duration = 1200;
      const start = performance.now();

      const tick = (now) => {
        const elapsed = now - start;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        el.textContent = Math.floor(target * eased);
        if (progress < 1) requestAnimationFrame(tick);
        else el.textContent = target;
      };

      requestAnimationFrame(tick);
    };

    const counterObserver = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            const el = entry.target.querySelector("[data-count]");
            if (el) animateCounter(el);
            counterObserver.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.3 }
    );

    document.querySelectorAll(".stat-item").forEach((item) => counterObserver.observe(item));
  }
});
