"""Email/message NLP engine.

  stage 1  hashed TF-IDF logistic regression       -> probability + top weighted terms (explainable)
  stage 2  MiniLM sentence-embedding classifier     -> probability robust to paraphrase
  intents  multilingual phrase lexicon (exact evidence spans) + semantic prototypes (paraphrase-level)
  memory   embedding similarity to phishing centroids learned from training data

Nothing here generates text: every category carries the exact phrase or the prototype it matched.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from functools import lru_cache

import joblib
import numpy as np

from ..config import get_settings
from .nlp_features import word_features

log = logging.getLogger(__name__)

# id -> (label, weight, [regex patterns across English / Hindi / Hinglish / Tamil / Tanglish])
INTENTS: dict[str, tuple[str, float, list[str]]] = {
    'urgency': ('Urgency / time pressure', 0.14, [
        r'\burgent(?:ly)?\b', r'\bimmediate(?:ly)?\b', r'\bwithin \d+ ?(?:hours?|hrs?|minutes?|mins?|days?)\b', r'\bas soon as possible\b', r'\basap\b',
        r'\b(?:today|tonight) only\b', r'\blast (?:chance|reminder|warning|notice)\b', r'\bfinal (?:notice|warning|reminder)\b', r'\bexpir(?:e|es|ed|ing|y)\b',
        r'\bact now\b', r'\bdeadline\b', r'\btime[- ]sensitive\b', r'turant', r'\babhi\b', r'aaj hi', r'तुरंत', r'अभी', r'உடனடியாக', r'இன்றே', r'udane'],),
    'fear': ('Threat / fear of loss', 0.14, [
        r'\b(?:will be|has been|have been|is being) (?:blocked|suspended|deactivated|disabled|terminated|closed|locked|restricted|frozen|deleted)\b',
        r'\bunauthori[sz]ed (?:access|activity|login|transaction)\b', r'\bsuspicious (?:activity|login|sign-?in|transaction)\b', r'\blegal action\b',
        r'\bpenalt(?:y|ies)\b', r'\bfine of\b', r'\bdisconnect(?:ed|ion)?\b', r'band ho jayega', r'block ho jayega', r'बंद हो जाएगा', r'துண்டிக்கப்படும்', r'முடக்கப்படும்'],),
    'account_suspension': ('Account suspension claim', 0.2, [
        r'\baccount (?:has been |will be |is )?(?:suspended|locked|blocked|disabled|deactivated|on hold|restricted|limited)\b', r'\b(?:suspend|deactivate|lock)(?:ed)? your account\b',
        r'\bmailbox (?:is )?(?:full|over quota|suspended|deactivat)', r'\bstorage (?:is )?(?:full|exceeded)\b'],),
    'credential_request': ('Asks for login credentials', 0.28, [
        r'\b(?:verify|confirm|validate|update|re-?enter|restore) (?:your )?(?:account|identity|login|credentials|password|details|information|email)\b',
        r'\b(?:log ?in|sign ?in) (?:to|now|here|below|immediately)\b', r'\benter your (?:password|pin|credentials|user ?id)\b', r'\bclick (?:here|below|the link) to (?:verify|login|log in|sign in|confirm|restore|unlock|reactivate)\b',
        r'login kar(?:ein|o|e)', r'लॉगिन करें', r'உள்நுழை'],),
    'otp_request': ('Asks for OTP / PIN / CVV', 0.34, [
        r'\b(?:share|send|tell|provide|give|forward) (?:me |us )?(?:the |your )?(?:otp|one[- ]time password|verification code|pin|mpin|cvv|upi pin)\b',
        r'\botp (?:received|sent) (?:to|on) your\b', r'\bread (?:out|me) the (?:otp|code)\b', r'otp (?:batao|bataiye|bhejo|share karo|dijiye)', r'ओटीपी', r'ஓடிபி', r'otp (?:sollunga|anuppunga)'],),
    'password_reset': ('Password reset lure', 0.16, [r'\breset (?:your )?password\b', r'\bpassword (?:will )?expir', r'\bchange your password\b', r'\bpassword reset request\b'],),
    'identity_verification': ('KYC / identity verification', 0.22, [
        r'\b(?:re-?)?kyc\b', r'\bpan(?: card)? (?:update|link|verification)\b', r'\baadhaa?r (?:update|link|verification|number)\b', r'\bverify your identity\b',
        r'केवाईसी', r'கேஒய்சி', r'\bupdate (?:your )?(?:kyc|pan|aadhaa?r)\b'],),
    'payment_request': ('Asks you to pay / transfer', 0.2, [
        r'\b(?:pay|transfer|send|deposit|remit) (?:rs\.?|₹|inr|\$|usd|the|a|an)? ?(?:amount|fee|fees|charges?|money|payment|\d)', r'\bprocessing fee\b', r'\bcustoms (?:duty|fee|charges?)\b',
        r'\brefundable deposit\b', r'\bregistration fee\b', r'\bclear (?:the |your )?(?:dues|pending (?:bill|payment))\b', r'paise bhej', r'पैसे भेज', r'பணம் (?:அனுப்ப|கட்ட)', r'kattanam'],),
    'upi_collect': ('UPI collect / "enter PIN to receive" trick', 0.34, [
        r'\b(?:enter|put) (?:your )?(?:upi )?pin to (?:receive|get|claim|accept)\b', r'\bscan (?:this|the) (?:qr|code) to (?:receive|get|claim)\b',
        r'\bapprove the (?:collect )?request to (?:receive|get)\b', r'\baccept (?:the )?request to (?:receive|get) (?:money|payment|refund|cashback)\b'],),
    'remote_access': ('Remote-access app request', 0.34, [r'\b(?:anydesk|teamviewer|quicksupport|rustdesk|airdroid|screen ?share app|ammyy)\b', r'\binstall (?:this|the) (?:app|apk)\b', r'\.apk\b'],),
    'attachment_lure': ('Attachment / document lure', 0.14, [
        r'\b(?:see|view|open|download|review) (?:the )?(?:attached|attachment|enclosed|document|invoice|file|pdf)\b', r'\bshared (?:a |an )?(?:document|file|folder) with you\b',
        r'\byou have (?:a )?(?:new )?(?:voicemail|fax|secure message|encrypted message)\b', r'\bdocusign\b'],),
    'executive_impersonation': ('Boss / executive request (BEC)', 0.22, [
        r'\b(?:are you|r u) (?:available|free|at your desk)\b', r'\b(?:need|want) (?:a |you to do a )?(?:quick |small )?favou?r\b', r'\bgift ?cards?\b',
        r'\bkeep (?:this|it) (?:confidential|between us|private)\b', r'\bi am (?:in a meeting|travelling|on a call)\b', r'\bwire transfer\b'],),
    'authority_impersonation': ('Claims to be police / government / bank authority', 0.2, [
        r'\b(?:police|cyber ?crime|cbi|ncb|narcotics|customs|enforcement directorate|income tax department|rbi|trai|court|magistrate)\b',
        r'\b(?:arrest|warrant|fir|summons|money laundering|drug parcel)\b', r'\bdigital arrest\b', r'\bvideo call (?:verification|statement)\b', r'கைது', r'गिरफ्तार'],),
    'reward_bait': ('Reward / lottery / prize bait', 0.2, [
        r'\b(?:you(?:\'ve| have)? won|winner|lottery|jackpot|lucky draw|prize|congratulations)\b', r'\bclaim (?:your )?(?:reward|prize|gift|cashback|refund|bonus)\b',
        r'\b(?:cashback|reward points?) (?:expir|credited|pending)', r'\bfree (?:gift|iphone|recharge|laptop)\b', r'inaam', r'इनाम', r'பரிசு'],),
    'invoice_fraud': ('Invoice / payment fraud', 0.16, [
        r'\b(?:overdue|outstanding|unpaid|pending) (?:invoice|payment|bill)\b', r'\b(?:changed|new|updated) (?:bank|banking|account) details\b', r'\bremittance advice\b', r'\bpayment confirmation\b'],),
    'delivery_scam': ('Parcel / delivery scam', 0.18, [
        r'\b(?:parcel|package|shipment|courier|consignment|delivery)\b.{0,60}\b(?:held|on hold|pending|failed|unable|re-?schedule|address|fee|customs)\b',
        r'\bupdate (?:your )?(?:delivery )?address\b', r'\bredelivery\b'],),
    'job_scam': ('Job / task / investment scam', 0.2, [
        r'\b(?:part[- ]time|work from home|online) job\b', r'\bearn (?:rs\.?|₹|\$)? ?\d[\d,]* (?:per|a|/) ?(?:day|daily|hour)\b', r'\b(?:like|rate) (?:youtube )?videos?\b.{0,40}\bearn',
        r'\bprepaid task\b', r'\bguaranteed returns?\b', r'\bdouble your money\b', r'\btrading (?:tips|group|signals)\b'],),
    'utility_disconnection': ('Electricity / utility disconnection scam', 0.24, [
        r'\b(?:electricity|power|eb|tneb|light|connection)\b.{0,60}\b(?:disconnect|cut|discontinued)', r'\bbill (?:not updated|pending)\b.{0,60}\b(?:tonight|today|\d+ ?pm)\b', r'மின் இணைப்பு', r'बिजली कनेक्शन'],),
    'secrecy': ('Asks you to keep it secret', 0.14, [r'\bdo not (?:tell|share|inform|disclose)\b.{0,30}\b(?:anyone|family|bank)\b', r'\bconfidential\b', r'kisi ko mat', r'यारிடமும் சொல்ல', r'யாரிடமும் சொல்ல'],),
    'generic_greeting': ('Generic greeting (not addressed to you by name)', 0.06, [r'\bdear (?:customer|user|client|member|account ?holder|sir/madam|valued customer|beneficiary)\b'],),
}
_COMPILED = {k: [re.compile(p, re.I) for p in v[2]] for k, v in INTENTS.items()}

# semantic prototypes: short descriptions of each scam intent; matched by embedding similarity (paraphrase-level)
PROTOTYPES: dict[str, list[str]] = {
    'credential_request': ['Please verify your account by signing in through the link below.', 'Confirm your login details to keep access to your mailbox.',
                           'Your employee account needs immediate validation, log in to continue.'],
    'account_suspension': ['Your account has been temporarily suspended due to unusual activity.', 'We will close your account unless you take action.'],
    'otp_request': ['Please share the one time password you just received to complete the process.', 'Tell me the code sent to your phone.'],
    'payment_request': ['Pay the pending fee now to avoid cancellation.', 'Transfer the processing charge to release your funds.'],
    'reward_bait': ['Congratulations, you have been selected to receive a cash prize.', 'Claim your reward before it expires.'],
    'delivery_scam': ['Your parcel could not be delivered, update your address and pay the redelivery fee.'],
    'invoice_fraud': ['Please process the attached overdue invoice today, our bank details have changed.'],
    'executive_impersonation': ['I need you to buy some gift cards for a client urgently, keep it between us.'],
    'authority_impersonation': ['This is the cyber crime police, a case has been registered against your Aadhaar number.'],
    'identity_verification': ['Update your KYC details immediately or your bank account will be blocked.'],
    'job_scam': ['Earn money daily from home by completing simple online tasks.'],
}


@dataclass
class Intent:
    id: str
    label: str
    weight: float
    evidence: list[str] = field(default_factory=list)
    spans: list[tuple[int, int]] = field(default_factory=list)
    source: str = 'lexicon'  # lexicon | semantic
    similarity: float | None = None


@dataclass
class NLPResult:
    score: float  # 0-100
    p_stage1: float | None
    p_stage2: float | None
    intent_score: float
    intents: list[Intent]
    top_terms: list[tuple[str, float]]
    campaign_similarity: float | None
    embedding: np.ndarray | None = None
    model_available: bool = True


class NLPEngine:
    def __init__(self) -> None:
        s = get_settings()
        self.model = None
        self.centroids = None
        self.encoder = None
        self.proto = None
        path = s.models_dir / 'email' / 'email_model.joblib'
        if path.exists():
            self.model = joblib.load(path)
            c = s.models_dir / 'email' / 'phish_centroids.npy'
            self.centroids = np.load(c) if c.exists() else None
        else:
            log.warning('email model missing at %s; NLP falls back to lexicon only', path)
        if s.enable_embeddings:
            try:
                from sentence_transformers import SentenceTransformer
                self.encoder = SentenceTransformer(s.embedding_model)
                self.proto = {k: self.encoder.encode(v, normalize_embeddings=True) for k, v in PROTOTYPES.items()}
            except Exception as e:  # model files absent (e.g. serverless build): stage 2 marked unavailable
                log.warning('embeddings unavailable: %s', e)

    def embed(self, text: str) -> np.ndarray | None:
        if self.encoder is None:
            return None
        return self.encoder.encode([text[:1500]], normalize_embeddings=True)[0]

    def _top_terms(self, text: str) -> list[tuple[str, float]]:
        """Exact per-term contributions (tf-idf value x coefficient) of the linear stage-1 model."""
        from sklearn.feature_extraction.text import HashingVectorizer
        pipe = self.model['stage1']
        hv, tfidf, lr = pipe.steps[0][1], pipe.steps[1][1], pipe.steps[2][1]
        X = tfidf.transform(hv.transform([text]))
        uniq = list(dict.fromkeys(word_features(text)))[:600]
        single = HashingVectorizer(analyzer=lambda s: [s], n_features=hv.n_features, alternate_sign=False, norm=None)
        cols = single.transform(uniq)
        names = {cols[i].indices[0]: n for i, n in enumerate(uniq) if len(cols[i].indices)}
        coef = lr.coef_[0]
        contrib = sorted(((names[j], float(coef[j] * v)) for j, v in zip(X.indices, X.data) if j in names), key=lambda kv: -kv[1])
        return [(n.split(':', 1)[1].replace('_', ' '), round(c, 3)) for n, c in contrib[:8] if c > 0]

    def analyze(self, text: str, embedding: np.ndarray | None = None) -> NLPResult:
        text = text[:20000]
        intents: dict[str, Intent] = {}
        for k, pats in _COMPILED.items():
            label, w, _ = INTENTS[k]
            for rx in pats:
                for m in rx.finditer(text):
                    it = intents.setdefault(k, Intent(k, label, w))
                    if len(it.evidence) < 3:
                        it.evidence.append(m.group(0))
                    it.spans.append((m.start(), m.end()))
        p1 = p2 = None
        top: list[tuple[str, float]] = []
        emb = embedding if embedding is not None else self.embed(text)
        if self.model:
            p1 = float(self.model['stage1'].predict_proba([text])[0, 1])
            top = self._top_terms(text)
            if emb is not None:
                p2 = float(self.model['stage2'].predict_proba(emb.reshape(1, -1))[0, 1])
        camp_sim = None
        if emb is not None:
            if self.centroids is not None:
                camp_sim = float(np.max(self.centroids @ emb))
            if self.proto:
                sents = [s.strip() for s in re.split(r'(?<=[.!?\n])\s+', text) if len(s.strip()) > 15][:40]
                if sents:
                    se = self.encoder.encode(sents, normalize_embeddings=True)
                    for k, P in self.proto.items():
                        sims = se @ P.T
                        i, j = np.unravel_index(np.argmax(sims), sims.shape)
                        sim = float(sims[i, j])
                        if sim >= 0.55 and k not in intents:
                            label, w, _ = INTENTS[k]
                            intents[k] = Intent(k, label, w * 0.85, [sents[i][:160]], [], 'semantic', round(sim, 3))
                        elif sim >= 0.55 and intents[k].similarity is None:
                            intents[k].similarity = round(sim, 3)
        lst = sorted(intents.values(), key=lambda i: -i.weight)
        intent_score = 1.0
        for it in lst:
            intent_score *= (1 - it.weight)
        intent_score = 1 - intent_score
        ps = [p for p in (p1, p2) if p is not None]
        p_ml = sum(ps) / len(ps) if ps else 0.0
        # The classifier alone over-flags transactional notices (training data labels commercial SMS spam as
        # phishing), so without any concrete scam intent its probability counts at 60%.
        if ps and not lst:
            combined = 0.6 * p_ml
        else:
            combined = 1 - (1 - p_ml) * (1 - 0.75 * intent_score) if ps else intent_score
        return NLPResult(score=round(100 * combined, 1), p_stage1=p1, p_stage2=p2, intent_score=round(intent_score, 3), intents=lst,
                         top_terms=top, campaign_similarity=camp_sim, embedding=emb, model_available=bool(self.model))


@lru_cache(maxsize=1)
def get_nlp_engine() -> NLPEngine:
    return NLPEngine()
