/**
 * Nivesh Kavach - Internationalization (i18n) Configuration
 * Easily extendable by adding a new language entry to LANGS and translations dictionary.
 */

const LANGS = [
  { code: "en", label: "English", speech_tag: "en-IN" },
  { code: "hi", label: "हिन्दी", speech_tag: "hi-IN" }
];

const TRANSLATIONS = {
  en: {
    app_title: "Nivesh Kavach",
    app_tagline: "Pause. Check. Then decide.",
    hero_desc: "A safety checker that analyses suspicious investment messages, screenshots, and links for Indian retail investors.",
    privacy_note: "🔒 Privacy First: Zero database. We never store your text or images. In-memory safety analysis only.",
    privacy_banner: "Safe & Anonymous: Your data is never sold, saved, or logged. Personal numbers and names are redacted prior to analysis.",
    
    // Tabs
    tab_text: "📝 Paste Text",
    tab_screenshot: "🖼️ Screenshot",
    tab_link: "🔗 Check Link",
    tab_voice: "🎙️ Speak",

    // Input fields
    text_placeholder: "Paste suspicious WhatsApp, Telegram, SMS, or social media investment message here...",
    text_hint: "Tip: Sensitive personal details (phones, PAN, Aadhaar, account numbers) are automatically redacted before analysis.",
    
    url_label: "Investment Link / URL to analyze:",
    url_placeholder: "e.g., http://invest-vip-profit.xyz/join or sebi-portal-kyc.com",
    url_notice: "⚠️ Safety Notice: We NEVER visit, fetch, or open user-submitted links. Only the link's text string structure is inspected for phishing signs.",

    image_label: "Upload Screenshot of Chat / Offer / Chart (Max 4 MB):",
    image_crop_warning: "⚠️ Crucial: Crop or blur your personal balance, bank details, and account numbers before uploading. Screenshots are processed in temporary memory only and re-encoded locally (max 1024px, EXIF data stripped).",
    image_selected: "Selected file:",

    voice_title: "Voice Input (Speech-to-Text)",
    voice_desc: "Speak the investment offer or message you received in your preferred language.",
    voice_cloud_notice: "ℹ️ Browser Notice: Voice input uses your browser's speech engine. Your device may send audio to a speech service to convert speech into text.",
    btn_start_recording: "🎙️ Start Speaking",
    btn_stop_recording: "⏹️ Stop Recording",
    voice_listening: "Listening... Please speak now.",
    voice_unsupported: "Speech recognition is not supported in this browser. Please use the Text tab.",

    // Action buttons
    btn_analyze: "🛡️ Analyze for Warning Signs",
    btn_analyzing: "⏳ Analyzing Warning Signs...",
    btn_clear: "🔄 Clear / Reset",
    btn_read_aloud: "🔊 Read Aloud",
    btn_stop_read: "⏹️ Stop Reading",
    voice_not_available: "Voice read-aloud is not available on this device in this language.",

    // Results screen
    results_title: "Safety Analysis Report",
    risk_level_title: "Risk Level Assessment",
    signals_title: "Identified Warning Signs & Red Flags",
    no_signals: "No high-risk warning patterns were flagged in this content.",
    why_dangerous_label: "Why this is dangerous:",
    evidence_label: "Identified Evidence:",
    claims_title: "Claims Requiring Independent Verification",
    claims_notice: "The content claims regulatory approval or registration. NEVER accept claims without checking official portals yourself.",
    how_to_verify_label: "How to verify:",
    explanation_title: "Simple Plain-Language Explanation",
    next_steps_title: "Recommended Safe Next Steps",
    official_links_title: "Authorized Regulators & Support Portals",
    official_links_notice: "Only visit verified regulatory and fraud helpline websites:",
    confidence_title: "Analysis Confidence",
    confidence_reasons: "Basis for confidence rating:",
    disclaimer_title: "Mandatory Regulatory Disclaimer",
    source_rule: "Deterministic Rule",
    source_ai: "AI Heuristic",

    // Risk levels
    level_low: "Low Risk Indicators",
    level_medium: "Moderate Risk Detected",
    level_high: "High Risk Detected",
    level_very_high: "Very High Risk (Critical Scam Signs)",

    // Errors
    error_empty_input: "Please provide some text, a link, or upload a screenshot to analyze.",
    error_server: "Failed to complete analysis. Please try again."
  },

  hi: {
    app_title: "निवेश कवच",
    app_tagline: "रुकें। जांचें। फिर निर्णय लें।",
    hero_desc: "भारतीय खुदरा निवेशकों के लिए संदिग्ध निवेश संदेशों, स्क्रीनशॉट्स और लिंक्स का सुरक्षा विश्लेषक।",
    privacy_note: "🔒 पूर्ण गोपनीयता: कोई डेटाबेस नहीं। हम आपका डेटा कभी संग्रहीत नहीं करते। केवल तात्कालिक मेमोरी में जांच होती है।",
    privacy_banner: "सुरक्षित एवं गोपनीय: आपकी जानकारी कभी स्टोर या लॉग नहीं होती। फोन नंबर और खाते का विवरण जांच से पहले हटा दिया जाता है।",

    // Tabs
    tab_text: "📝 संदेश लिखें / पेस्ट करें",
    tab_screenshot: "🖼️ स्क्रीनशॉट",
    tab_link: "🔗 लिंक जांचें",
    tab_voice: "🎙️ बोलकर बताएं",

    // Input fields
    text_placeholder: "संदिग्ध व्हाट्सऐप, टेलीग्राम, एसएमएस या सोशल मीडिया संदेश यहाँ पेस्ट करें...",
    text_hint: "सुझाव: फोन नंबर, पैन, आधार और बैंक खाता संख्या जांच से पहले अपने आप [REDACTED] कर दिए जाते हैं।",

    url_label: "जांच के लिए वेबसाइट का लिंक (URL):",
    url_placeholder: "जैसे: http://invest-vip-profit.xyz/join या sebi-portal-kyc.com",
    url_notice: "⚠️ सुरक्षा सूचना: हम कभी भी संदिग्ध लिंक पर नहीं जाते और न ही वेबसाइट खोलते हैं। केवल लिंक के शब्दों और बनावट की जांच की जाती है।",

    image_label: "चैट, ऑफर या मुनाफे के स्क्रीनशॉट की फोटो (अधिकतम 4 MB):",
    image_crop_warning: "⚠️ जरूरी सूचना: स्क्रीनशॉट से अपना बैंक बैलेंस, खाता संख्या या निजी जानकारी पहले ही क्रॉप या छिपा लें। फोटो केवल अस्थायी मेमोरी में प्रोसेस की जाती है और आपके डिवाइस पर री-साइज (अधिकतम 1024px) होती है।",
    image_selected: "चुनी गई फाइल:",

    voice_title: "आवाज से इनपुट (Speech-to-Text)",
    voice_desc: "संदिग्ध निवेश ऑफर या संदेश को बोलकर दर्ज करें।",
    voice_cloud_notice: "ℹ️ ब्राउज़र सूचना: आवाज इनपुट आपके ब्राउज़र की स्पीच तकनीक का उपयोग करता है। आवाज को टेक्स्ट में बदलने के लिए ब्राउज़र सेवा का उपयोग हो सकता है।",
    btn_start_recording: "🎙️ बोलना शुरू करें",
    btn_stop_recording: "⏹️ बोलना बंद करें",
    voice_listening: "सुन रहे हैं... कृपया अब बोलें।",
    voice_unsupported: "इस ब्राउज़र में आवाज पहचान उपलब्ध नहीं है। कृपया टेक्स्ट टैब का उपयोग करें।",

    // Action buttons
    btn_analyze: "🛡️ खतरे के संकेतों की जांच करें",
    btn_analyzing: "⏳ संकेतों का विश्लेषण हो रहा है...",
    btn_clear: "🔄 नया विश्लेषण / रीसेट",
    btn_read_aloud: "🔊 बोलकर सुनाएं",
    btn_stop_read: "⏹️ आवाज बंद करें",
    voice_not_available: "इस डिवाइस पर इस भाषा में आवाज उपलब्ध नहीं है।",

    // Results screen
    results_title: "सुरक्षा जांच रिपोर्ट",
    risk_level_title: "जोखिम स्तर का आकलन",
    signals_title: "पाए गए खतरे और चेतावनी संकेत",
    no_signals: "इस सामग्री में कोई गंभीर चेतावनी संकेत नहीं पाए गए।",
    why_dangerous_label: "यह क्यों खतरनाक है:",
    evidence_label: "पहचाना गया प्रमाण:",
    claims_title: "दावे जिनका सत्यापन जरूरी है",
    claims_notice: "संदेश में सरकारी मंज़ूरी या रजिस्ट्रेशन का दावा किया गया है। आधिकारिक पोर्टल पर जांच किए बिना कभी विश्वास न करें।",
    how_to_verify_label: "जांच कैसे करें:",
    explanation_title: "सरल भाषा में व्याख्या",
    next_steps_title: "सुरक्षा के लिए अगले कदम",
    official_links_title: "आधिकारिक नियामक एवं हेल्पलाइन पोर्टल",
    official_links_notice: "केवल सरकार और सेबी की आधिकारिक वेबसाइटों पर ही भरोसा करें:",
    confidence_title: "जांच की विश्वसनीयता (Confidence)",
    confidence_reasons: "विश्वसनीयता का आधार:",
    disclaimer_title: "अनिवार्य विनियामक अस्वीकरण (Disclaimer)",
    source_rule: "नियम आधारित",
    source_ai: "एआई विश्लेषण",

    // Risk levels
    level_low: "कम जोखिम के संकेत",
    level_medium: "मध्यम जोखिम (सावधानी बरतें)",
    level_high: "उच्च जोखिम (धोखाधड़ी का अंदेशा)",
    level_very_high: "अत्यधिक जोखिम (गंभीर ठगी के लक्षण)",

    // Errors
    error_empty_input: "कृपया जांच के लिए टेक्स्ट लिखें, लिंक डालें या स्क्रीनशॉट अपलोड करें।",
    error_server: "विश्लेषण पूरा करने में समस्या आई। कृपया पुनः प्रयास करें।"
  }
};
