/**
 * Nivesh Kavach - Main Application Logic
 * Client-side features:
 * - Dynamic i18n language translation
 * - Client-side image downscaling to max 1024px & EXIF stripping via Canvas
 * - Web Speech API voice input with cloud disclosure
 * - SpeechSynthesis read-aloud with device voice detection
 * - Transparent rendering of deterministic rules + AI signals
 */

let currentLangCode = "en";
let selectedProcessedImageBlob = null;
let isSpeaking = false;
let currentReportTextForSpeech = "";

document.addEventListener("DOMContentLoaded", () => {
  initLanguageSelector();
  setupTabs();
  setupImageInput();
  setupAnalyzeButton();
  setupSpeechSynthesis();
  applyLanguage(currentLangCode);
});

/* ----------------------------------------------------
 * Language / i18n
 * ---------------------------------------------------- */
function initLanguageSelector() {
  const select = document.getElementById("langSelect");
  if (!select) return;

  select.innerHTML = "";
  LANGS.forEach(l => {
    const opt = document.createElement("option");
    opt.value = l.code;
    opt.textContent = l.label;
    select.appendChild(opt);
  });

  select.addEventListener("change", (e) => {
    currentLangCode = e.target.value;
    applyLanguage(currentLangCode);
  });
}

function applyLanguage(langCode) {
  const t = TRANSLATIONS[langCode] || TRANSLATIONS["en"];

  // Update text content of all data-i18n elements
  document.querySelectorAll("[data-i18n]").forEach(el => {
    const key = el.getAttribute("data-i18n");
    if (t[key]) {
      el.textContent = t[key];
    }
  });

  // Update placeholders
  document.querySelectorAll("[data-i18n-placeholder]").forEach(el => {
    const key = el.getAttribute("data-i18n-placeholder");
    if (t[key]) {
      el.setAttribute("placeholder", t[key]);
    }
  });
}

/* ----------------------------------------------------
 * Tabs Navigation
 * ---------------------------------------------------- */
function setupTabs() {
  const tabButtons = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");

  tabButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      tabButtons.forEach(b => b.classList.remove("active"));
      tabContents.forEach(c => c.classList.remove("active"));

      btn.classList.add("active");
      const targetId = btn.getAttribute("data-tab");
      const targetContent = document.getElementById(targetId);
      if (targetContent) {
        targetContent.classList.add("active");
      }
    });
  });
}

/* ----------------------------------------------------
 * Client-Side Image Resizing & EXIF Stripping
 * ---------------------------------------------------- */
function setupImageInput() {
  const fileInput = document.getElementById("imageFileInput");
  const previewBox = document.getElementById("imagePreviewBox");
  const previewImg = document.getElementById("imagePreview");

  if (!fileInput) return;

  fileInput.addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (!file) {
      selectedProcessedImageBlob = null;
      previewBox.style.display = "none";
      return;
    }

    if (file.size > 4 * 1024 * 1024) {
      alert("File exceeds maximum allowed size of 4 MB. Please choose a smaller image.");
      fileInput.value = "";
      return;
    }

    const reader = new FileReader();
    reader.onload = (event) => {
      const img = new Image();
      img.onload = () => {
        // Downscale to max 1024px and re-encode to strip EXIF
        const maxDim = 1024;
        let width = img.width;
        let height = img.height;

        if (width > maxDim || height > maxDim) {
          if (width > height) {
            height = Math.round((height * maxDim) / width);
            width = maxDim;
          } else {
            width = Math.round((width * maxDim) / height);
            height = maxDim;
          }
        }

        const canvas = document.createElement("canvas");
        canvas.width = width;
        canvas.height = height;
        const ctx = canvas.getContext("2d");
        ctx.drawImage(img, 0, 0, width, height);

        // Export clean JPEG without EXIF metadata
        canvas.toBlob((blob) => {
          selectedProcessedImageBlob = blob;
          previewImg.src = canvas.toDataURL("image/jpeg", 0.88);
          previewBox.style.display = "block";
        }, "image/jpeg", 0.88);
      };
      img.src = event.target.result;
    };
    reader.readAsDataURL(file);
  });
}


/* ----------------------------------------------------
 * SpeechSynthesis (Read Aloud)
 * ---------------------------------------------------- */
function setupSpeechSynthesis() {
  const readBtn = document.getElementById("readAloudBtn");
  if (!readBtn) return;

  readBtn.addEventListener("click", () => {
    const t = TRANSLATIONS[currentLangCode];

    if (!('speechSynthesis' in window)) {
      alert(t.voice_not_available);
      return;
    }

    if (isSpeaking) {
      window.speechSynthesis.cancel();
      isSpeaking = false;
      readBtn.textContent = t.btn_read_aloud;
      return;
    }

    if (!currentReportTextForSpeech) return;

    const utterance = new SpeechSynthesisUtterance(currentReportTextForSpeech);
    const voices = window.speechSynthesis.getVoices();
    
    // Pick voice whose lang matches
    const matchedVoice = voices.find(v => v.lang.toLowerCase().startsWith(currentLangCode));
    if (matchedVoice) {
      utterance.voice = matchedVoice;
    } else {
      // If Hindi and no exact hi voice, check for Indian English or let browser attempt
      const fallbackVoice = voices.find(v => v.lang.toLowerCase().includes("in"));
      if (fallbackVoice) {
        utterance.voice = fallbackVoice;
      }
    }

    utterance.onend = () => {
      isSpeaking = false;
      readBtn.textContent = t.btn_read_aloud;
    };

    utterance.onerror = () => {
      isSpeaking = false;
      readBtn.textContent = t.btn_read_aloud;
    };

    isSpeaking = true;
    readBtn.textContent = t.btn_stop_read;
    window.speechSynthesis.speak(utterance);
  });
}

/* ----------------------------------------------------
 * Form Submission & API Analysis
 * ---------------------------------------------------- */
function setupAnalyzeButton() {
  const analyzeBtn = document.getElementById("analyzeBtn");
  const clearBtn = document.getElementById("clearBtn");
  const resultsContainer = document.getElementById("resultsContainer");

  analyzeBtn.addEventListener("click", async () => {
    const t = TRANSLATIONS[currentLangCode];
    const textVal = document.getElementById("textInput").value.trim();
    const urlVal = document.getElementById("urlInput").value.trim();

    if (!textVal && !urlVal && !selectedProcessedImageBlob) {
      alert(t.error_empty_input);
      return;
    }

    analyzeBtn.disabled = true;
    analyzeBtn.textContent = t.btn_analyzing;

    const formData = new FormData();
    if (textVal) formData.append("text", textVal);
    if (urlVal) formData.append("url", urlVal);
    if (selectedProcessedImageBlob) {
      formData.append("image", selectedProcessedImageBlob, "screenshot.jpg");
    }
    formData.append("language", currentLangCode);

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        body: formData
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || t.error_server);
      }

      const data = await response.json();
      renderResults(data);
      resultsContainer.style.display = "block";
      resultsContainer.scrollIntoView({ behavior: "smooth" });
    } catch (err) {
      alert(err.message || t.error_server);
    } finally {
      analyzeBtn.disabled = false;
      analyzeBtn.textContent = t.btn_analyze;
    }
  });

  clearBtn.addEventListener("click", () => {
    document.getElementById("textInput").value = "";
    document.getElementById("urlInput").value = "";
    document.getElementById("imageFileInput").value = "";
    document.getElementById("imagePreviewBox").style.display = "none";
    selectedProcessedImageBlob = null;
    resultsContainer.style.display = "none";
    if (window.speechSynthesis) window.speechSynthesis.cancel();
    isSpeaking = false;
    currentReportTextForSpeech = "";
  });
}

/* ----------------------------------------------------
 * Results Rendering (Accessible: Color + Icon + Words)
 * ---------------------------------------------------- */
function renderResults(data) {
  const t = TRANSLATIONS[currentLangCode];
  const riskCard = document.getElementById("riskCard");
  const riskBadge = document.getElementById("riskBadge");
  const riskHeadline = document.getElementById("riskHeadline");
  const riskScoreText = document.getElementById("riskScoreText");

  const risk = data.risk || { level: "Low", score: 0, headline: "" };
  const levelStr = (risk.level || "Low").toLowerCase();

  // Reset classes
  riskCard.className = "risk-card";
  let icon = "🛡️";
  let levelWord = t.level_low;

  if (levelStr.includes("very") || levelStr.includes("critical") || risk.score >= 70) {
    riskCard.classList.add("risk-very-high");
    icon = "🚨";
    levelWord = t.level_very_high;
  } else if (levelStr.includes("high") || risk.score >= 45) {
    riskCard.classList.add("risk-high");
    icon = "⚠️";
    levelWord = t.level_high;
  } else if (levelStr.includes("medium") || risk.score >= 20) {
    riskCard.classList.add("risk-medium");
    icon = "⚡";
    levelWord = t.level_medium;
  } else {
    riskCard.classList.add("risk-low");
    icon = "🟢";
    levelWord = t.level_low;
  }

  riskBadge.innerHTML = `<span>${icon}</span> <span>${levelWord}</span>`;
  riskHeadline.textContent = risk.headline;
  riskScoreText.textContent = `Calculated Warning Score: ${risk.score}/100`;

  // Plain Explanation
  const explanationBox = document.getElementById("explanationContent");
  explanationBox.textContent = data.plain_explanation || "";

  // Prepare SpeechSynthesis text
  currentReportTextForSpeech = `${levelWord}. ${risk.headline}. ${data.plain_explanation || ""}`;

  // Signals List
  const signalsList = document.getElementById("signalsList");
  signalsList.innerHTML = "";

  if (!data.signals || data.signals.length === 0) {
    const noSigMsg = document.createElement("p");
    noSigMsg.style.fontStyle = "italic";
    noSigMsg.textContent = t.no_signals;
    signalsList.appendChild(noSigMsg);
  } else {
    data.signals.forEach(sig => {
      const card = document.createElement("div");
      card.className = "signal-card";

      const sourceLabel = sig.source === "ai" ? t.source_ai : t.source_rule;
      const categoryName = sig.category ? sig.category.replace(/_/g, " ") : "Warning";

      card.innerHTML = `
        <div class="signal-header">
          <span class="signal-category">⚠️ ${escapeHtml(categoryName)}</span>
          <span class="signal-tag">${escapeHtml(sourceLabel)}</span>
        </div>
        ${sig.evidence ? `<div class="signal-evidence"><strong>${t.evidence_label}</strong> "${escapeHtml(sig.evidence)}"</div>` : ""}
        <div class="signal-danger"><strong>${t.why_dangerous_label}</strong> ${escapeHtml(sig.why_dangerous || "")}</div>
      `;
      signalsList.appendChild(card);
    });
  }

  // Claims to Verify
  const claimsSection = document.getElementById("claimsSection");
  const claimsList = document.getElementById("claimsList");
  claimsList.innerHTML = "";

  if (data.claims_to_verify && data.claims_to_verify.length > 0) {
    claimsSection.style.display = "block";
    data.claims_to_verify.forEach(claimObj => {
      const cDiv = document.createElement("div");
      cDiv.className = "claim-card";
      cDiv.innerHTML = `
        <div class="claim-text">🔍 ${escapeHtml(claimObj.claim || "")}</div>
        <div class="claim-how"><strong>${t.how_to_verify_label}</strong> ${escapeHtml(claimObj.how_to_verify || "")}</div>
      `;
      claimsList.appendChild(cDiv);
    });
  } else {
    claimsSection.style.display = "none";
  }

  // Next Steps
  const nextStepsList = document.getElementById("nextStepsList");
  nextStepsList.innerHTML = "";
  (data.next_steps || []).forEach(step => {
    const li = document.createElement("li");
    li.textContent = step;
    nextStepsList.appendChild(li);
  });

  // Official Links
  const officialLinksList = document.getElementById("officialLinksList");
  officialLinksList.innerHTML = "";
  (data.official_links || []).forEach(link => {
    const a = document.createElement("a");
    a.className = "official-link-card";
    a.href = link.url;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    a.innerHTML = `
      <div class="link-title">🏛️ ${escapeHtml(link.label || "")} ↗</div>
      <div class="link-url">${escapeHtml(link.url || "")}</div>
      <div class="link-note">${escapeHtml(link.note || "")}</div>
    `;
    officialLinksList.appendChild(a);
  });

  // Confidence & Reasons
  const conf = data.confidence || { level: "Medium", reasons: [] };
  document.getElementById("confidenceLevelText").textContent = `Level: ${conf.level}`;
  const reasonsList = document.getElementById("confidenceReasonsList");
  reasonsList.innerHTML = "";
  (conf.reasons || []).forEach(r => {
    const li = document.createElement("li");
    li.textContent = r;
    reasonsList.appendChild(li);
  });

  // Disclaimer
  document.getElementById("disclaimerText").textContent = data.disclaimer || t.disclaimer_title;
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
