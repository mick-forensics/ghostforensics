const form = document.querySelector("#analysisForm");
const riskScore = document.querySelector("#riskScore");
const riskLevel = document.querySelector("#riskLevel");
const meterFill = document.querySelector("#meterFill");
const scamTypeList = document.querySelector("#scamTypeList");
const flagsList = document.querySelector("#flagsList");
const stepsList = document.querySelector("#stepsList");
const whyList = document.querySelector("#whyList");
const statusChip = document.querySelector(".status-chip");

const knowledgeFilePaths = [
  "data/scam-keywords.json",
  "data/phishing-patterns.json",
  "data/job-scam-patterns.json",
  "data/investment-scam-patterns.json",
  "data/payment-redflags.json",
  "data/identity-theft-patterns.json",
  "data/romance-scam-patterns.json",
  "data/tech-support-patterns.json",
  "data/government-impersonation-patterns.json",
  "data/rental-scam-patterns.json",
  "data/lottery-advance-fee-patterns.json",
  "data/delivery-smishing-patterns.json",
  "data/safe-steps.json"
];

// Local browser security can block JSON fetches from file://.
// For best local testing, open index.html with the VS Code Live Server extension.
const fallbackKnowledgeBase = [
  {
    category: "General scam language",
    indicators: [
      "urgent",
      "act now",
      "immediately",
      "today",
      "limited",
      "limited time",
      "final notice",
      "last chance",
      "expires today",
      "within 24 hours",
      "kindly",
      "dear customer",
      "dear valued customer",
      "do the needful",
      "this is to inform you",
      "deployed overseas",
      "US Army",
      "military",
      "can't meet in person",
      "cant meet in person",
      "cannot meet in person",
      "god bless",
      "warrant has been issued",
      "arrest",
      "criminal charges",
      "do not shut down",
      "do not ignore this message",
      "this is your final warning",
      "remote access",
      "remote support",
      "guaranteed",
      "no risk",
      "double your money",
      "free money",
      "congratulations",
      "you won",
      "selected",
      "telegram",
      "whatsapp",
      "iTunes gift card"
    ],
    riskWeight: 14,
    explanation: "Scam messages often use pressure, generic greetings, awkward wording, or unrealistic promises to make people respond quickly.",
    recommendation: "Slow down, verify the sender through a separate trusted channel, and do not click links or reply with sensitive information."
  },
  {
    category: "Phishing and account access",
    indicators: [
      "password",
      "verification code",
      "one-time code",
      "one time code",
      "2fa",
      "otp",
      "login code",
      "verify your account",
      "confirm your account",
      "account suspended",
      "dear valued customer",
      "permanently suspended",
      "account limited",
      "verify within 24 hours",
      "chase",
      "paypal",
      "amazon",
      "wells fargo",
      "bank of america",
      "irs",
      "ssa",
      "medicare",
      "fbi",
      "uscis",
      "usps",
      "fedex",
      "ups",
      "dhl",
      "microsoft",
      "apple",
      "google",
      "norton",
      "mcafee",
      "-alert.com",
      "-secure.com",
      "-verify.com",
      "-notice.com"
    ],
    riskWeight: 22,
    explanation: "Requests for passwords, login links, or verification codes can let someone take over your account.",
    recommendation: "Never share passwords or one-time codes. Go directly to the official website or app to check your account."
  },
  {
    category: "Job scam patterns",
    indicators: [
      "no interview required",
      "without an interview",
      "interview is not required",
      "no need for interview",
      "hired without interview",
      "remote job",
      "work from home",
      "work-from-home",
      "data entry",
      "virtual assistant",
      "personal assistant",
      "equipment check",
      "training check",
      "start immediately",
      "payroll setup",
      "set up payroll",
      "payroll department",
      "hr portal",
      "employment verification form",
      "w-4 form",
      "w4 form",
      "i-9 form",
      "i9 form",
      "onboarding form"
    ],
    riskWeight: 24,
    explanation: "Fake job offers often promise fast remote work, skip normal interviews, or ask for onboarding details before the employer is verified.",
    recommendation: "Verify the company on its official website, use the official careers page, and do not send payroll or identity details to an unverified recruiter."
  },
  {
    category: "Investment Scam",
    indicators: [
      "guaranteed returns",
      "guaranteed profit",
      "30% weekly",
      "double your money",
      "10x returns",
      "private group",
      "private trading group",
      "vip group",
      "my mentor helped me",
      "register through my link",
      "minimum deposit to activate your account",
      "turned $500 into $14,000",
      "crypto investment",
      "bitcoin investment",
      "online relationship",
      "mentor",
      "minimum deposit"
    ],
    minimumMatches: 2,
    riskWeight: 70,
    explanation: "Investment scams often promise guaranteed returns, private trading access, or unusually high profits, especially around crypto. Real investments carry risk and are never guaranteed.",
    recommendation: "Do not deposit money through links from strangers or private groups. Verify any investment professional independently and avoid crypto offers that promise guaranteed returns."
  },
  {
    category: "Payment red flags",
    indicators: [
      "gift card",
      "iTunes gift card",
      "itunes card",
      "google play card",
      "crypto",
      "bitcoin",
      "ethereum",
      "zelle",
      "cash app",
      "venmo",
      "wire",
      "wire transfer",
      "payment",
      "send money",
      "paying extra for trouble",
      "paying extra",
      "overpayment",
      "over paid",
      "overpaid",
      "deposit",
      "upfront fee",
      "shipping fee",
      "bank information",
      "bank info",
      "banking information",
      "bank account",
      "routing number",
      "account number",
      "direct deposit",
      "debit card",
      "online banking"
    ],
    riskWeight: 24,
    explanation: "Scammers often request payment methods or bank details that are hard to reverse or can expose you to financial theft.",
    recommendation: "Do not send money or share bank details until you independently verify the person, company, and reason for payment."
  },
  {
    category: "Identity theft patterns",
    indicators: [
      "id picture",
      "photo id",
      "picture of your id",
      "photo of your id",
      "identity document",
      "driver's license",
      "drivers license",
      "passport",
      "social security",
      "ssn",
      "national id",
      "date of birth",
      "full name",
      "phone number",
      "email address",
      "address",
      "copy of your id"
    ],
    riskWeight: 26,
    explanation: "Requests for ID photos, Social Security numbers, passports, or similar documents can lead to identity theft.",
    recommendation: "Do not upload identity documents until you confirm the request through an official, trusted channel."
  },
  {
    category: "Romance Scam",
    indicators: [
      "oil rig",
      "offshore",
      "engineer on a rig",
      "north sea",
      "missionary",
      "doctor abroad",
      "military overseas",
      "i saw your profile and couldn't stop thinking about you",
      "i feel like we have a real connection",
      "i don't have many people to talk to",
      "meet you when i get back",
      "small favor",
      "emergency satellite",
      "emergency phone credits",
      "i promise i will pay you back",
      "i know this is random but"
    ],
    minimumMatches: 2,
    riskWeight: 85,
    explanation: "Romance scammers build emotional connection over days or weeks before asking for money. Victims lose an average of $10,000+. Never send money to someone you have not met in person.",
    recommendation: "Stop all contact immediately. Do not send money under any circumstances, even if the story seems real and emotional. Report the profile to the platform. You can report romance scams to the FTC at reportfraud.ftc.gov."
  },
  {
    category: "Tech Support Scam",
    indicators: [
      "microsoft has detected",
      "apple has detected",
      "google has detected",
      "your computer has been infected",
      "do not shut down your computer",
      "certified technician",
      "remote support",
      "call our toll-free number immediately",
      "we will remove the virus remotely",
      "one-time fee",
      "your data is at risk"
    ],
    minimumMatches: 2,
    riskWeight: 85,
    explanation: "Microsoft, Apple, and Google never contact users about viruses by phone or email. Never allow remote access to your computer from an unsolicited contact. Never pay a tech support fee with gift cards.",
    recommendation: "Do not call the number. Do not allow remote access to your computer. Hang up immediately if you are on the phone. Run a scan with your existing antivirus software. Microsoft, Apple, and Google never contact users this way."
  },
  {
    category: "Government Impersonation Scam",
    indicators: [
      "internal revenue service",
      "irs",
      "social security administration",
      "ssa",
      "medicare",
      "fbi",
      "dea",
      "immigration",
      "uscis",
      "warrant has been issued for your arrest",
      "avoid immediate legal action",
      "this is your final warning",
      "criminal charges",
      "legal action",
      "settle your balance",
      "irs-",
      "ssa-",
      "medicare-",
      "fbi-"
    ],
    minimumMatches: 2,
    riskWeight: 90,
    explanation: "Government agencies like the IRS never demand immediate payment by phone, never threaten arrest for unpaid taxes, and never accept gift cards or wire transfers as payment. If you receive this type of message, hang up and call the official agency number directly.",
    recommendation: "The IRS and other government agencies never demand immediate payment by phone, never threaten arrest for unpaid taxes, and never accept gift cards. Hang up and call the official agency number directly to verify any real notices."
  },
  {
    category: "Rental Scam",
    indicators: [
      "missionary in ghana",
      "abroad",
      "overseas",
      "rental",
      "rent",
      "apartment",
      "unit",
      "cannot show the unit in person",
      "can't show the unit in person",
      "will mail you the keys once you pay",
      "first month and security deposit",
      "employment information for background check",
      "fully furnished, utilities included, pet friendly",
      "gmail.com"
    ],
    minimumMatches: 3,
    riskWeight: 85,
    explanation: "Legitimate landlords always allow property viewings before accepting payment. Never pay rent or a deposit without seeing the property in person or through a verified agent. Never send deposit via Zelle or Cash App.",
    recommendation: "Never pay rent or a deposit without viewing the property in person or through a licensed agent. Legitimate landlords do not ask for payment before showing the unit. Report to the platform where the listing appeared."
  },
  {
    category: "Lottery and Advance Fee Scam",
    indicators: [
      "you have been selected as a winner",
      "your email was randomly chosen",
      "processing fee to claim your prize",
      "administration fee",
      "release fee",
      "transfer fee",
      "pay a fee to receive your winnings",
      "lottery",
      "sweepstakes",
      "international prize",
      "you have won"
    ],
    minimumMatches: 2,
    riskWeight: 90,
    explanation: "Legitimate lotteries and prizes never require you to pay a fee to claim winnings. If you did not enter a contest, you cannot have won it. Pay to receive money is always a scam.",
    recommendation: "You cannot win a lottery you did not enter. No legitimate prize requires a fee to claim. Stop all contact and do not send any money."
  },
  {
    category: "Delivery and Smishing Scam",
    indicators: [
      "usps",
      "fedex",
      "ups",
      "dhl",
      "your package has been suspended",
      "incomplete address",
      "delivery attempt unsuccessful",
      "pay a redelivery fee",
      "small fee",
      "usps-",
      "fedex-",
      "ups-",
      "dhl-",
      "click here to update your shipping details",
      "package returned to sender"
    ],
    minimumMatches: 2,
    riskWeight: 85,
    explanation: "Real delivery companies never charge redelivery fees by clicking a link in a text or email. Small fees like $2.99 are designed to capture your credit card details. Always track packages directly on the official carrier website.",
    recommendation: "Do not click the link. Go directly to the official carrier website (usps.com, fedex.com, ups.com) and enter your tracking number there. Real carriers never charge redelivery fees through SMS or email links."
  },
  {
    category: "Safe next steps",
    indicators: [],
    riskWeight: 0,
    explanation: "General safety guidance for suspicious messages.",
    recommendation: "Save screenshots, stop responding if the message feels suspicious, and report it to the platform, email provider, bank, or local consumer protection agency."
  }
];

const scamCategoryProfiles = [
  {
    name: "Job Scam",
    indicators: [
      "job",
      "position",
      "hiring",
      "remote job",
      "work from home",
      "data entry",
      "virtual assistant",
      "no interview required",
      "payroll setup",
      "onboarding form",
      "equipment check",
      "training check"
    ],
    explanation: "The message looks like a job or hiring offer and includes patterns often seen in fake recruiting or fake onboarding."
  },
  {
    name: "Phishing",
    indicators: [
      "password",
      "verification code",
      "one-time code",
      "one time code",
      "otp",
      "2fa",
      "login code",
      "verify your account",
      "confirm your account",
      "account suspended",
      "dear valued customer",
      "permanently suspended",
      "account limited",
      "verify within 24 hours",
      "chase",
      "paypal",
      "amazon",
      "wells fargo",
      "bank of america",
      "click the link"
    ],
    explanation: "The message appears to be trying to get account access, login details, or verification codes."
  },
  {
    name: "Marketplace Scam",
    indicators: [
      "marketplace",
      "facebook marketplace",
      "seller",
      "buyer",
      "shipping",
      "shipping fee",
      "courier",
      "item",
      "listing",
      "deposit",
      "hold the item",
      "cash app",
      "zelle"
    ],
    explanation: "The message has buying, selling, shipping, or off-platform payment language often seen in marketplace scams."
  },
  {
    name: "Investment Scam",
    indicators: [
      "investment",
      "invest",
      "profit",
      "returns",
      "guaranteed returns",
      "guaranteed profit",
      "guaranteed",
      "no risk",
      "30% weekly",
      "double your money",
      "10x returns",
      "crypto",
      "bitcoin",
      "crypto investment",
      "bitcoin investment",
      "trading",
      "forex",
      "portfolio",
      "private group",
      "private trading group",
      "vip group",
      "my mentor helped me",
      "register through my link",
      "minimum deposit to activate your account",
      "turned $500 into $14,000"
    ],
    explanation: "The message suggests money-making claims, guaranteed returns, crypto, or trading language."
  },
  {
    name: "Identity Theft",
    indicators: [
      "photo id",
      "id picture",
      "picture of your id",
      "driver's license",
      "drivers license",
      "passport",
      "ssn",
      "social security",
      "address",
      "date of birth",
      "full name",
      "phone number",
      "email address",
      "identity document"
    ],
    explanation: "The message asks for personal identity information that could be used to impersonate someone."
  },
  {
    name: "Tech Support Scam",
    indicators: [
      "tech support",
      "support agent",
      "computer infected",
      "your computer has been infected",
      "virus detected",
      "microsoft has detected",
      "apple has detected",
      "google has detected",
      "microsoft support",
      "apple support",
      "remote access",
      "remote support",
      "certified technician",
      "do not shut down your computer",
      "call our toll-free number immediately",
      "we will remove the virus remotely",
      "anydesk",
      "teamviewer",
      "screen share",
      "security alert"
    ],
    explanation: "The message resembles fake support warnings that try to get remote access, payment, or account information."
  },
  {
    name: "Government Impersonation Scam",
    indicators: [
      "internal revenue service",
      "irs",
      "social security administration",
      "ssa",
      "medicare",
      "fbi",
      "dea",
      "immigration",
      "uscis",
      "warrant has been issued",
      "warrant has been issued for your arrest",
      "avoid immediate legal action",
      "this is your final warning",
      "criminal charges",
      "legal action",
      "settle your balance"
    ],
    explanation: "The message impersonates a government agency and uses threats or urgent payment pressure."
  },
  {
    name: "Rental Scam",
    indicators: [
      "rental",
      "rent",
      "apartment",
      "unit",
      "landlord",
      "missionary in ghana",
      "abroad",
      "overseas",
      "cannot show the unit in person",
      "can't show the unit in person",
      "will mail you the keys once you pay",
      "first month and security deposit",
      "employment information for background check",
      "fully furnished, utilities included, pet friendly"
    ],
    explanation: "The message resembles a fake rental listing or landlord request designed to collect deposits before a real viewing."
  },
  {
    name: "Lottery and Advance Fee Scam",
    indicators: [
      "you have been selected as a winner",
      "your email was randomly chosen",
      "processing fee to claim your prize",
      "administration fee",
      "release fee",
      "transfer fee",
      "pay a fee to receive your winnings",
      "lottery",
      "sweepstakes",
      "international prize",
      "you have won"
    ],
    explanation: "The message claims a prize or payout but asks for a fee before releasing money."
  },
  {
    name: "Delivery and Smishing Scam",
    indicators: [
      "usps",
      "fedex",
      "ups",
      "dhl",
      "package",
      "delivery",
      "your package has been suspended",
      "incomplete address",
      "delivery attempt unsuccessful",
      "pay a redelivery fee",
      "small fee",
      "click here to update your shipping details",
      "package returned to sender"
    ],
    explanation: "The message impersonates a delivery carrier and pushes a link, fee, or personal information request."
  },
  {
    name: "Payment Fraud",
    indicators: [
      "gift card",
      "zelle",
      "cash app",
      "venmo",
      "wire",
      "crypto",
      "bitcoin",
      "bank information",
      "banking information",
      "routing number",
      "account number",
      "upfront fee",
      "payment",
      "send money",
      "paying extra for trouble",
      "paying extra",
      "overpayment",
      "over paid",
      "overpaid",
      "deposit"
    ],
    explanation: "The message focuses on payment methods, bank details, or money movement that can be difficult to reverse."
  },
  {
    name: "Romance Scam",
    indicators: [
      "love",
      "relationship",
      "soulmate",
      "dating",
      "widowed",
      "oil rig",
      "offshore",
      "engineer on a rig",
      "north sea",
      "missionary",
      "doctor abroad",
      "deployed overseas",
      "us army",
      "military",
      "military overseas",
      "i saw your profile and couldn't stop thinking about you",
      "i feel like we have a real connection",
      "i don't have many people to talk to",
      "meet you when i get back",
      "small favor",
      "emergency satellite",
      "emergency phone credits",
      "i promise i will pay you back",
      "i know this is random but",
      "can't meet in person",
      "cant meet in person",
      "cannot meet in person",
      "need money",
      "travel money",
      "medical emergency",
      "my dear",
      "telegram",
      "whatsapp"
    ],
    explanation: "The message includes relationship-building or personal emergency language often used to build trust before asking for money."
  }
];

let knowledgeBase = fallbackKnowledgeBase;

loadKnowledgeBase();

form.addEventListener("submit", (event) => {
  event.preventDefault();

  const formData = new FormData(form);
  const caseType = String(formData.get("caseType") || "");
  const message = String(formData.get("messageText") || "");
  const email = String(formData.get("emailInput") || "");
  const url = String(formData.get("urlInput") || "");

  const analysis = analyzeScam({ caseType, message, email, url });
  renderResults(analysis);
});

async function loadKnowledgeBase() {
  try {
    const files = await Promise.all(
      knowledgeFilePaths.map(async (path) => {
        const response = await fetch(path);

        if (!response.ok) {
          throw new Error(`Could not load ${path}`);
        }

        return response.json();
      })
    );

    knowledgeBase = files;
    updateStatus("Knowledge Base Loaded");
  } catch (error) {
    knowledgeBase = fallbackKnowledgeBase;
    updateStatus("Offline Fallback Ready");
    console.info("Using embedded fallback data. Live Server is recommended for local JSON testing.", error);
  }
}

function analyzeScam({ caseType, message, email, url }) {
  const analysisText = `${caseType} ${message} ${email} ${url}`.toLowerCase();
  const matchedCategories = [];
  const matchedRecommendations = new Set();
  const matchedIndicatorSet = new Set();
  const flags = [];
  let score = 0;

  knowledgeBase.forEach((entry) => {
    const matchedIndicators = findMatchedIndicators(entry.indicators, analysisText);
    const minimumMatches = Number(entry.minimumMatches) || 1;

    if (matchedIndicators.length < minimumMatches) {
      return;
    }

    score += Number(entry.riskWeight) || 0;
    matchedCategories.push(entry.category);
    matchedRecommendations.add(entry.recommendation);
    matchedIndicators.forEach((indicator) => matchedIndicatorSet.add(indicator));
    flags.push(`${entry.category}: ${entry.explanation} Matched: ${matchedIndicators.join(", ")}.`);
  });

  const domainFlag = analyzeDomainMismatch(email, url);

  if (domainFlag) {
    score += domainFlag.riskWeight;
    matchedCategories.push(domainFlag.category);
    matchedRecommendations.add(domainFlag.recommendation);
    flags.push(`${domainFlag.category}: ${domainFlag.explanation}`);
  }

  const brandImpersonationFlag = analyzeBrandImpersonation(email, url, analysisText);

  if (brandImpersonationFlag) {
    score += brandImpersonationFlag.riskWeight;
    matchedCategories.push(brandImpersonationFlag.category);
    matchedRecommendations.add(brandImpersonationFlag.recommendation);
    flags.push(`${brandImpersonationFlag.category}: ${brandImpersonationFlag.explanation}`);
  }

  if (matchedCategories.includes("Job scam patterns") && matchedCategories.includes("Payment red flags")) {
    score += 18;
    flags.push("Combined employment and payment risk: A job message that also asks for money or bank details is more suspicious.");
  }

  if (matchedCategories.includes("Job scam patterns") && matchedCategories.includes("Identity theft patterns")) {
    score += 18;
    flags.push("Combined employment and identity risk: A job message that asks for ID documents can be a fake onboarding scam.");
  }

  if (hasJobOfferSignal(caseType, analysisText) && hasIndicator(matchedIndicatorSet, ["no interview required", "without an interview", "interview is not required", "no need for interview", "hired without interview"]) && hasIndicator(matchedIndicatorSet, ["telegram", "whatsapp"])) {
    score += 24;
    flags.push("Strong fake job signal: Job offer language, no interview, and Telegram or WhatsApp together are a major employment scam warning sign.");
  }

  if (hasJobOfferSignal(caseType, analysisText) && hasIndicator(matchedIndicatorSet, ["payroll setup", "set up payroll", "payroll department"]) && hasIndicator(matchedIndicatorSet, ["bank information", "bank info", "banking information", "bank account", "routing number", "account number", "direct deposit"])) {
    score += 26;
    flags.push("Strong fake payroll signal: Payroll setup plus banking information can be a fake onboarding attempt to collect financial details.");
  }

  if (hasIndicator(matchedIndicatorSet, ["photo id", "id picture", "picture of your id", "photo of your id", "driver's license", "drivers license", "ssn", "social security", "address", "bank information", "bank info", "banking information", "bank account", "routing number", "account number"])) {
    score += 16;
    flags.push("Strong identity or financial data request: The message asks for information that could be used for identity theft or unauthorized financial access.");
  }

  if (hasIdentityBundleRequest(analysisText)) {
    score += 24;
    matchedCategories.push("Identity theft patterns");
    flags.push("Bundled personal information request: Asking for full name, phone number, and email together can be used to build an identity theft profile.");
  }

  if (hasMilitaryOrOverseasPaymentPattern(analysisText, matchedIndicatorSet)) {
    score += 22;
    matchedCategories.push("Payment red flags");
    flags.push("Military or overseas payment pattern: Deployment, military identity, inability to meet, or overpayment language combined with payment pressure is a common scam setup.");
  }

  if (hasGodBlessPaymentPattern(analysisText, matchedIndicatorSet)) {
    score += 18;
    matchedCategories.push("Payment red flags");
    flags.push("Trust-building payment request: Religious sign-off language combined with a payment request can be used to lower suspicion before asking for money.");
  }

  const strongCategorySignal = detectStrongCategorySignal({ text: analysisText, email, url, matchedIndicatorSet });

  if (strongCategorySignal) {
    score = Math.max(score, strongCategorySignal.minimumScore);
    matchedCategories.push(strongCategorySignal.name);
    matchedRecommendations.add(getCategoryRecommendation(strongCategorySignal.name));
    flags.push(strongCategorySignal.flag);
  }

  if (new Set(matchedCategories).size >= 3) {
    score += 15;
    flags.push("Multiple red flag categories: Three or more different warning-sign groups matched, so the overall risk is higher.");
  }

  if (!message.trim() && !email.trim() && !url.trim()) {
    score = 0;
    flags.push("No details entered: Paste a message, email, or URL to scan for warning signs.");

    const scamType = {
      name: "Unknown",
      confidence: 0,
      explanation: "There was not enough category-specific evidence to choose one scam type."
    };

    return {
      score,
      level: getRiskLevel(score),
      scamType,
      flags,
      steps: buildNextSteps(score, matchedRecommendations),
      why: buildWhyThisMatters(score, matchedCategories)
    };
  }

  const scamType = determineScamCategory(analysisText, caseType, matchedCategories, matchedIndicatorSet, strongCategorySignal);
  score = enforceConfidenceRiskFloor(score, scamType, flags);
  score = clampScore(score);

  return {
    score,
    level: getRiskLevel(score),
    scamType,
    flags,
    steps: buildNextSteps(score, matchedRecommendations),
    why: buildWhyThisMatters(score, matchedCategories)
  };
}

function findMatchedIndicators(indicators, text) {
  return indicators.filter((indicator) => text.includes(indicator.toLowerCase()));
}

function hasJobOfferSignal(caseType, text) {
  return caseType === "job offer" || text.includes("job") || text.includes("position") || text.includes("hiring");
}

function hasIndicator(matchedIndicatorSet, indicators) {
  return indicators.some((indicator) => matchedIndicatorSet.has(indicator));
}

function hasIdentityBundleRequest(text) {
  const hasFullName = text.includes("full name") || text.includes("complete name") || text.includes("legal name");
  const hasPhone = text.includes("phone") || text.includes("mobile number") || text.includes("cell number");
  const hasEmail = text.includes("email") || text.includes("e-mail");

  return hasFullName && hasPhone && hasEmail;
}

function hasMilitaryOrOverseasPaymentPattern(text, matchedIndicatorSet) {
  const hasMilitarySignal = ["deployed overseas", "us army", "military", "military overseas"].some((indicator) => text.includes(indicator));
  const cannotMeet = ["can't meet in person", "cant meet in person", "cannot meet in person"].some((indicator) => text.includes(indicator));
  const hasOverpayment = hasIndicator(matchedIndicatorSet, ["paying extra for trouble", "paying extra", "overpayment", "over paid", "overpaid"]);

  return (hasMilitarySignal || cannotMeet) && (hasOverpayment || hasPaymentRequest(text, matchedIndicatorSet));
}

function hasGodBlessPaymentPattern(text, matchedIndicatorSet) {
  return text.includes("god bless") && hasPaymentRequest(text, matchedIndicatorSet);
}

function hasPaymentRequest(text, matchedIndicatorSet) {
  const paymentIndicators = [
    "payment",
    "send money",
    "gift card",
    "itunes gift card",
    "itunes card",
    "google play card",
    "crypto",
    "bitcoin",
    "ethereum",
    "zelle",
    "cash app",
    "venmo",
    "wire",
    "wire transfer",
    "deposit",
    "upfront fee",
    "shipping fee",
    "bank information",
    "bank info",
    "banking information",
    "bank account",
    "routing number",
    "account number",
    "direct deposit",
    "debit card",
    "online banking"
  ];

  return hasIndicator(matchedIndicatorSet, paymentIndicators) || paymentIndicators.some((indicator) => text.includes(indicator));
}

function detectStrongCategorySignal({ text, email, url, matchedIndicatorSet }) {
  const signals = [
    {
      name: "Government Impersonation Scam",
      minimumScore: 90,
      confidence: 95,
      flag: "Government impersonation override: Agency name, arrest or legal threat, and gift card or wire payment language are present together.",
      when: () => hasGovernmentAgency(text) && hasArrestOrLegalThreat(text) && hasGiftCardOrWirePayment(text, matchedIndicatorSet)
    },
    {
      name: "Lottery and Advance Fee Scam",
      minimumScore: 90,
      confidence: 92,
      flag: "Lottery or advance-fee override: Prize or winner language appears together with a required processing, release, transfer, or administration fee.",
      when: () => hasLotteryWinClaim(text) && hasAdvanceFee(text)
    },
    {
      name: "Investment Scam",
      minimumScore: 90,
      confidence: 90,
      flag: "High-risk investment pattern: Multiple guaranteed-profit, private group, crypto, mentor, or minimum-deposit signals are present.",
      when: () => hasHighRiskInvestmentPattern(text)
    },
    {
      name: "Delivery and Smishing Scam",
      minimumScore: 85,
      confidence: 90,
      flag: "Delivery smishing override: Carrier name, suspicious carrier-like domain, and small fee or redelivery-fee language are present together.",
      when: () => hasDeliveryCarrier(text) && hasSuspiciousBrandDomain(email, url, text, ["USPS", "FedEx", "UPS", "DHL"]) && hasSmallDeliveryFee(text)
    },
    {
      name: "Tech Support Scam",
      minimumScore: 85,
      confidence: 90,
      flag: "Tech support override: Tech-company impersonation, a phone number or toll-free call request, and remote-access or infection language are present together.",
      when: () => hasTechCompanyImpersonation(text) && hasPhoneNumber(text) && hasRemoteSupportOrInfectionSignal(text)
    },
    {
      name: "Rental Scam",
      minimumScore: 85,
      confidence: 90,
      flag: "Rental scam override: Rental language, overseas landlord story, inability to show the property, and direct payment request are present together.",
      when: () => hasRentalLanguage(text) && hasOverseasLandlordSignal(text) && hasCannotShowPropertySignal(text) && hasRentalPaymentRequest(text, matchedIndicatorSet)
    },
    {
      name: "Romance Scam",
      minimumScore: 85,
      confidence: 88,
      flag: "Romance scam override: Emotional connection or isolation language appears with overseas, oil-rig, military, missionary, or doctor-abroad claims.",
      when: () => hasRomanceOccupationSignal(text) && hasRomanceEmotionalManipulation(text)
    }
  ];

  return signals.find((signal) => signal.when()) || null;
}

function hasGovernmentAgency(text) {
  return ["internal revenue service", "irs", "social security administration", "ssa", "medicare", "fbi", "dea", "immigration", "uscis"].some((indicator) => text.includes(indicator));
}

function hasArrestOrLegalThreat(text) {
  return ["warrant has been issued", "arrest", "avoid immediate legal action", "this is your final warning", "criminal charges", "legal action"].some((indicator) => text.includes(indicator));
}

function hasGiftCardOrWirePayment(text, matchedIndicatorSet) {
  return hasIndicator(matchedIndicatorSet, ["gift card", "itunes gift card", "itunes card", "wire", "wire transfer"]) || ["gift card", "itunes gift card", "itunes card", "wire", "wire transfer"].some((indicator) => text.includes(indicator));
}

function hasLotteryWinClaim(text) {
  return ["you have been selected as a winner", "your email was randomly chosen", "lottery", "sweepstakes", "international prize", "you have won"].some((indicator) => text.includes(indicator));
}

function hasAdvanceFee(text) {
  return ["processing fee", "processing fee to claim your prize", "administration fee", "release fee", "transfer fee", "pay a fee to receive your winnings", "fee to claim"].some((indicator) => text.includes(indicator));
}

function hasHighRiskInvestmentPattern(text) {
  const investmentSignals = [
    "guaranteed returns",
    "guaranteed profit",
    "30% weekly",
    "double your money",
    "10x returns",
    "private group",
    "private trading group",
    "vip group",
    "my mentor helped me",
    "register through my link",
    "minimum deposit to activate your account",
    "turned $500 into $14,000",
    "minimum deposit"
  ];
  const pigButcheringSignals = ["online relationship", "crypto", "crypto investment", "bitcoin", "guaranteed returns", "guaranteed profit"];
  const investmentMatchCount = investmentSignals.filter((indicator) => text.includes(indicator)).length;
  const hasPigButcheringPattern = (text.includes("online relationship") || text.includes("relationship")) && (text.includes("crypto") || text.includes("bitcoin")) && (text.includes("guaranteed returns") || text.includes("guaranteed profit"));

  return investmentMatchCount >= 3 || hasPigButcheringPattern || pigButcheringSignals.filter((indicator) => text.includes(indicator)).length >= 4;
}

function hasDeliveryCarrier(text) {
  return ["usps", "fedex", "ups", "dhl"].some((indicator) => text.includes(indicator));
}

function hasSmallDeliveryFee(text) {
  return text.includes("pay a redelivery fee") || text.includes("small fee") || /\$\s?\d{1,2}(?:\.\d{2})?/.test(text);
}

function hasTechCompanyImpersonation(text) {
  return ["microsoft has detected", "apple has detected", "google has detected", "microsoft", "apple", "google", "norton", "mcafee"].some((indicator) => text.includes(indicator));
}

function hasPhoneNumber(text) {
  return text.includes("toll-free") || text.includes("toll free") || /(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}/.test(text);
}

function hasRemoteSupportOrInfectionSignal(text) {
  return ["remote access", "remote support", "remove the virus remotely", "your computer has been infected", "virus detected", "do not shut down your computer", "your data is at risk"].some((indicator) => text.includes(indicator));
}

function hasRentalLanguage(text) {
  return ["rental", "rent", "apartment", "unit", "landlord", "lease", "property"].some((indicator) => text.includes(indicator));
}

function hasOverseasLandlordSignal(text) {
  return ["missionary in ghana", "abroad", "overseas"].some((indicator) => text.includes(indicator));
}

function hasCannotShowPropertySignal(text) {
  return ["cannot show the unit in person", "can't show the unit in person", "cannot show the property", "can't show the property", "will mail you the keys once you pay"].some((indicator) => text.includes(indicator));
}

function hasRentalPaymentRequest(text, matchedIndicatorSet) {
  return hasIndicator(matchedIndicatorSet, ["zelle", "cash app", "wire", "wire transfer", "deposit", "first month and security deposit"]) || ["zelle", "cash app", "wire", "wire transfer", "deposit", "first month and security deposit"].some((indicator) => text.includes(indicator));
}

function hasRomanceOccupationSignal(text) {
  const occupationSignal = ["oil rig", "offshore", "engineer on a rig", "north sea", "missionary", "doctor abroad", "military overseas", "deployed overseas"].some((indicator) => text.includes(indicator));
  const oilRigEngineer = text.includes("oil rig") && text.includes("engineer");

  return occupationSignal || oilRigEngineer;
}

function hasRomanceEmotionalManipulation(text) {
  return [
    "i saw your profile and couldn't stop thinking about you",
    "i feel like we have a real connection",
    "i don't have many people to talk to",
    "meet you when i get back",
    "small favor",
    "emergency satellite",
    "emergency phone credits",
    "i promise i will pay you back",
    "i know this is random but",
    "love",
    "relationship",
    "my dear"
  ].some((indicator) => text.includes(indicator)) || (text.includes("oil rig") && text.includes("engineer"));
}

function getCategoryRecommendation(categoryName) {
  const knowledgeEntry = knowledgeBase.find((entry) => entry.category === categoryName);

  if (knowledgeEntry?.recommendation) {
    return knowledgeEntry.recommendation;
  }

  const recommendations = {
    "Romance Scam": "Stop all contact immediately. Do not send money under any circumstances, even if the story seems real and emotional. Report the profile to the platform. You can report romance scams to the FTC at reportfraud.ftc.gov.",
    "Tech Support Scam": "Do not call the number. Do not allow remote access to your computer. Hang up immediately if you are on the phone. Run a scan with your existing antivirus software. Microsoft, Apple, and Google never contact users this way.",
    "Government Impersonation Scam": "The IRS and other government agencies never demand immediate payment by phone, never threaten arrest for unpaid taxes, and never accept gift cards. Hang up and call the official agency number directly to verify any real notices.",
    "Rental Scam": "Never pay rent or a deposit without viewing the property in person or through a licensed agent. Legitimate landlords do not ask for payment before showing the unit. Report to the platform where the listing appeared.",
    "Lottery and Advance Fee Scam": "You cannot win a lottery you did not enter. No legitimate prize requires a fee to claim. Stop all contact and do not send any money.",
    "Delivery and Smishing Scam": "Do not click the link. Go directly to the official carrier website (usps.com, fedex.com, ups.com) and enter your tracking number there. Real carriers never charge redelivery fees through SMS or email links."
  };

  return recommendations[categoryName] || "Verify this message through an official channel before responding, clicking links, or sending money or personal information.";
}

function enforceConfidenceRiskFloor(score, scamType, flags) {
  const { name, confidence } = scamType;

  if (confidence >= 70 && (name === "Romance Scam" || name === "Investment Scam") && score < 85) {
    flags.push("Confidence-risk alignment: Romance and crypto investment scam confidence of 70% or higher requires a high-risk score of at least 85.");
    return 85;
  }

  if (confidence >= 70 && score < getCategoryMinimumScore(name)) {
    const minimumScore = getCategoryMinimumScore(name);
    flags.push(`Category risk floor: ${name} requires a high-risk score of at least ${minimumScore}.`);
    return minimumScore;
  }

  if (confidence >= 90 && score < 80) {
    flags.push("Confidence-risk alignment: A 90% or higher scam-type confidence requires a high-risk score of at least 80.");
    return 80;
  }

  if (confidence >= 70 && score < 65) {
    flags.push("Confidence-risk alignment: A 70% or higher scam-type confidence requires a high-risk score of at least 65.");
    return 65;
  }

  return score;
}

function getCategoryMinimumScore(categoryName) {
  const minimumScores = {
    "Romance Scam": 85,
    "Tech Support Scam": 85,
    "Government Impersonation Scam": 90,
    "Rental Scam": 85,
    "Lottery and Advance Fee Scam": 90,
    "Delivery and Smishing Scam": 85
  };

  return minimumScores[categoryName] || 65;
}

function determineScamCategory(text, caseType, matchedCategories, matchedIndicatorSet, strongCategorySignal) {
  if (strongCategorySignal) {
    const profile = scamCategoryProfiles.find((category) => category.name === strongCategorySignal.name);

    return {
      name: strongCategorySignal.name,
      confidence: strongCategorySignal.confidence,
      explanation: profile?.explanation || strongCategorySignal.flag
    };
  }

  const categoryScores = scamCategoryProfiles.map((profile) => {
    let score = profile.indicators.filter((indicator) => text.includes(indicator)).length * 10;

    if (matchedCategories.includes(profile.name)) {
      score += 35;
    }

    if (profile.name === "Job Scam" && (caseType === "job offer" || matchedCategories.includes("Job scam patterns"))) {
      score += 25;
    }

    if (profile.name === "Phishing" && matchedCategories.includes("Phishing and account access")) {
      score += 25;
    }

    if (profile.name === "Phishing" && matchedCategories.includes("Brand impersonation")) {
      score += 25;
    }

    if (profile.name === "Identity Theft" && matchedCategories.includes("Identity theft patterns")) {
      score += 30;
    }

    if (profile.name === "Payment Fraud" && matchedCategories.includes("Payment red flags")) {
      score += 25;
    }

    if (profile.name === "Investment Scam" && (caseType === "investment" || matchedCategories.includes("Investment Scam"))) {
      score += 25;
    }

    if (profile.name === "Marketplace Scam" && caseType === "marketplace") {
      score += 20;
    }

    if (profile.name === "Job Scam" && hasIndicator(matchedIndicatorSet, ["no interview required", "payroll setup", "banking information", "bank information", "photo id"])) {
      score += 15;
    }

    if (profile.name === "Tech Support Scam" && hasTechCompanyImpersonation(text) && hasRemoteSupportOrInfectionSignal(text)) {
      score += 25;
    }

    if (profile.name === "Government Impersonation Scam" && hasGovernmentAgency(text) && hasArrestOrLegalThreat(text)) {
      score += 25;
    }

    if (profile.name === "Delivery and Smishing Scam" && hasDeliveryCarrier(text) && hasSmallDeliveryFee(text)) {
      score += 25;
    }

    if (profile.name === "Rental Scam" && hasRentalLanguage(text) && hasOverseasLandlordSignal(text)) {
      score += 25;
    }

    if (profile.name === "Lottery and Advance Fee Scam" && hasLotteryWinClaim(text)) {
      score += 25;
    }

    if (profile.name === "Romance Scam" && hasRomanceOccupationSignal(text) && hasRomanceEmotionalManipulation(text)) {
      score += 30;
    }

    return {
      ...profile,
      score
    };
  });

  categoryScores.sort((a, b) => b.score - a.score);

  const best = categoryScores[0];

  if (!best || best.score === 0) {
    return {
      name: "Unknown",
      confidence: 0,
      explanation: "There was not enough category-specific evidence to choose one scam type."
    };
  }

  const totalScore = categoryScores.reduce((sum, category) => sum + category.score, 0);
  const relativeConfidence = totalScore > 0 ? Math.round((best.score / totalScore) * 100) : 0;
  const confidence = Math.max(35, Math.min(95, relativeConfidence + 20));

  return {
    name: best.name,
    confidence,
    explanation: best.explanation
  };
}

function analyzeDomainMismatch(email, url) {
  const emailDomain = extractEmailDomain(email);
  const webDomain = extractDomain(url);

  if (!emailDomain || !webDomain || domainsAppearRelated(emailDomain, webDomain)) {
    return null;
  }

  return {
    category: "Mismatched email and domain",
    riskWeight: 14,
    explanation: "The sender email domain does not appear to match the website or domain provided.",
    recommendation: "Check the sender address carefully and verify the website by typing the official address yourself."
  };
}

function analyzeBrandImpersonation(email, url, text) {
  const suspiciousDomains = getAllDomains(email, url, text)
    .map((domain) => getBrandImpersonation(domain))
    .filter(Boolean);
  const phishingLanguage = [
    "dear valued customer",
    "permanently suspended",
    "account limited",
    "verify within 24 hours",
    "verify your account",
    "confirm your account",
    "warrant has been issued",
    "this is your final warning",
    "your computer has been infected",
    "do not shut down your computer",
    "delivery attempt unsuccessful",
    "incomplete address"
  ].some((indicator) => text.includes(indicator));

  if (suspiciousDomains.length === 0 && !phishingLanguage) {
    return null;
  }

  const brandDetails = suspiciousDomains.length > 0
    ? ` Suspicious domain signal: ${[...new Set(suspiciousDomains)].join(", ")}.`
    : "";

  return {
    category: "Brand impersonation",
    riskWeight: suspiciousDomains.length > 0 ? 26 : 18,
    explanation: `The message or domain uses bank, marketplace, or payment-brand impersonation signals such as generic greetings, account limitation language, urgent verification, or brand names inside suspicious domains.${brandDetails}`,
    recommendation: "Do not use links in the message. Open the official app or type the known official domain directly, then check account notifications there."
  };
}

function extractDomain(value) {
  const trimmed = value.trim().toLowerCase();

  if (!trimmed) {
    return "";
  }

  try {
    const url = trimmed.includes("://") ? new URL(trimmed) : new URL(`https://${trimmed}`);
    return url.hostname.replace(/^www\./, "");
  } catch {
    return trimmed.replace(/^www\./, "").split("/")[0];
  }
}

function extractEmailDomain(value) {
  const match = value.trim().toLowerCase().match(/@([a-z0-9.-]+\.[a-z]{2,})$/i);
  return match ? match[1].replace(/^www\./, "") : "";
}

function getAllDomains(email, url, text) {
  const domains = [extractEmailDomain(email), extractDomain(url)].filter(Boolean);
  const domainMatches = text.match(/\b(?:https?:\/\/)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/[^\s]*)?/gi) || [];

  domainMatches.forEach((domain) => {
    domains.push(extractDomain(domain));
  });

  return [...new Set(domains.filter(Boolean))];
}

function hasSuspiciousBrandDomain(email, url, text, brandNames) {
  return getAllDomains(email, url, text).some((domain) => {
    const impersonation = getBrandImpersonation(domain);
    return brandNames.some((brandName) => impersonation.startsWith(`${brandName} in `));
  });
}

function domainsAppearRelated(emailDomain, webDomain) {
  const emailRoot = getRootDomain(emailDomain);
  const webRoot = getRootDomain(webDomain);
  return emailRoot === webRoot || emailDomain.endsWith(`.${webRoot}`) || webDomain.endsWith(`.${emailRoot}`);
}

function getRootDomain(domain) {
  const parts = domain.split(".").filter(Boolean);
  return parts.length >= 2 ? parts.slice(-2).join(".") : domain;
}

function getBrandImpersonation(domain) {
  const normalizedDomain = domain.toLowerCase().replace(/[^a-z0-9.]/g, "");
  const rootDomain = getRootDomain(normalizedDomain);
  const brandDomains = [
    { brand: "Chase", tokens: ["chase"], officialRoots: ["chase.com"] },
    { brand: "PayPal", tokens: ["paypal"], officialRoots: ["paypal.com"] },
    { brand: "Amazon", tokens: ["amazon"], officialRoots: ["amazon.com"] },
    { brand: "Wells Fargo", tokens: ["wellsfargo", "wellsfargobank"], officialRoots: ["wellsfargo.com"] },
    { brand: "Bank of America", tokens: ["bankofamerica", "bofa"], officialRoots: ["bankofamerica.com"] },
    { brand: "IRS", tokens: ["irs"], officialRoots: ["irs.gov"] },
    { brand: "SSA", tokens: ["ssa", "socialsecurity"], officialRoots: ["ssa.gov"] },
    { brand: "Medicare", tokens: ["medicare"], officialRoots: ["medicare.gov"] },
    { brand: "FBI", tokens: ["fbi"], officialRoots: ["fbi.gov"] },
    { brand: "USCIS", tokens: ["uscis"], officialRoots: ["uscis.gov"] },
    { brand: "USPS", tokens: ["usps"], officialRoots: ["usps.com"] },
    { brand: "FedEx", tokens: ["fedex"], officialRoots: ["fedex.com"] },
    { brand: "UPS", tokens: ["ups"], officialRoots: ["ups.com"] },
    { brand: "DHL", tokens: ["dhl"], officialRoots: ["dhl.com"] },
    { brand: "Microsoft", tokens: ["microsoft"], officialRoots: ["microsoft.com"] },
    { brand: "Apple", tokens: ["apple"], officialRoots: ["apple.com"] },
    { brand: "Google", tokens: ["google"], officialRoots: ["google.com"] },
    { brand: "Norton", tokens: ["norton"], officialRoots: ["norton.com"] },
    { brand: "McAfee", tokens: ["mcafee"], officialRoots: ["mcafee.com"] }
  ];

  const matchedBrand = brandDomains.find((entry) => {
    const containsBrand = entry.tokens.some((token) => normalizedDomain.includes(token));
    const isOfficial = entry.officialRoots.includes(rootDomain) || entry.officialRoots.some((officialRoot) => normalizedDomain.endsWith(`.${officialRoot}`));

    return containsBrand && !isOfficial;
  });

  return matchedBrand ? `${matchedBrand.brand} in ${domain}` : "";
}

function clampScore(score) {
  return Math.max(0, Math.min(100, score));
}

function getRiskLevel(score) {
  if (score >= 65) {
    return "High";
  }

  if (score >= 35) {
    return "Medium";
  }

  return "Low";
}

function buildNextSteps(score, matchedRecommendations) {
  const safeSteps = knowledgeBase.find((entry) => entry.category === "Safe next steps");
  const steps = Array.from(matchedRecommendations);

  if (score >= 65) {
    steps.unshift("Treat this as high risk until proven otherwise. Stop responding and keep records of the message.");
  }

  if (safeSteps) {
    steps.push(safeSteps.recommendation);
  }

  if (steps.length === 0) {
    steps.push("No major red flags were found, but still verify unexpected messages through an official channel.");
  }

  return [...new Set(steps)];
}

function buildWhyThisMatters(score, matchedCategories) {
  const categories = new Set(matchedCategories);
  const reasons = [];

  if (categories.has("Identity theft patterns")) {
    reasons.push("Identity theft risk: ID photos, Social Security numbers, birth dates, and addresses can be used to open accounts or impersonate you.");
  }

  if (categories.has("Payment red flags")) {
    reasons.push("Financial information risk: Bank details, routing numbers, payment apps, and crypto requests can lead to stolen funds or payments you cannot easily reverse.");
  }

  if (categories.has("Job scam patterns")) {
    reasons.push("Fake job onboarding risk: Scammers may pretend to hire you quickly so they can collect payroll details, identity documents, or money before you realize the job is fake.");
  }

  if (categories.has("Investment Scam")) {
    reasons.push("Investment risk: Guaranteed returns, private trading groups, and crypto deposit requests are common ways scammers push victims into irreversible payments.");
  }

  if (categories.has("Romance Scam")) {
    reasons.push("Romance scam risk: Emotional connection, isolation, overseas stories, and money requests can pressure victims into sending funds to someone they have never met.");
  }

  if (categories.has("Tech Support Scam")) {
    reasons.push("Tech support risk: Unsolicited virus warnings and remote-access requests can lead to stolen files, account takeover, or fraudulent support payments.");
  }

  if (categories.has("Government Impersonation Scam")) {
    reasons.push("Government impersonation risk: Threats of arrest or legal action are used to force rushed payments that real agencies do not demand by gift card or wire.");
  }

  if (categories.has("Rental Scam")) {
    reasons.push("Rental scam risk: Fake landlords often demand deposits before viewings, then disappear after collecting Zelle, Cash App, or wire payments.");
  }

  if (categories.has("Lottery and Advance Fee Scam")) {
    reasons.push("Advance-fee risk: Prize messages that require a fee before releasing winnings are designed to collect money or personal information.");
  }

  if (categories.has("Delivery and Smishing Scam")) {
    reasons.push("Delivery smishing risk: Small redelivery fees and carrier-like links are used to capture payment cards, logins, or personal information.");
  }

  if (reasons.length === 0) {
    if (score >= 65) {
      reasons.push("This message shows strong indicators of a scam attempt. Treat it as suspicious until independently verified through official channels.");
    } else {
      reasons.push("No major identity, financial, or fake onboarding pattern was found, but unexpected messages should still be verified through official channels.");
    }
  }

  return reasons;
}

function renderResults({ score, level, scamType, flags, steps, why }) {
  riskScore.textContent = score;
  riskLevel.textContent = level;
  riskLevel.className = `risk-level ${level.toLowerCase()}`;
  meterFill.style.width = `${score}%`;
  meterFill.style.background = getMeterColor(level);

  scamTypeList.innerHTML = "";
  flagsList.innerHTML = "";
  stepsList.innerHTML = "";
  whyList.innerHTML = "";

  scamTypeList.appendChild(createListItem(`${scamType.name} (${scamType.confidence}% confidence): ${scamType.explanation}`));

  flags.forEach((flag) => {
    flagsList.appendChild(createListItem(flag));
  });

  steps.forEach((step) => {
    stepsList.appendChild(createListItem(step));
  });

  why.forEach((reason) => {
    whyList.appendChild(createListItem(reason));
  });
}

function createListItem(text) {
  const item = document.createElement("li");
  item.textContent = text;
  return item;
}

function getMeterColor(level) {
  if (level === "High") {
    return "var(--high)";
  }

  if (level === "Medium") {
    return "var(--medium)";
  }

  return "var(--low)";
}

function updateStatus(text) {
  if (!statusChip) {
    return;
  }

  const pulse = statusChip.querySelector(".pulse");
  statusChip.textContent = "";

  if (pulse) {
    statusChip.appendChild(pulse);
  }

  statusChip.append(text);
}
