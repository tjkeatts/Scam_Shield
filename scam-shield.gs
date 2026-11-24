/**
 * Scam Shield for Gmail — Apps Script
 *
 * Maintains two Gmail filters that act at the moment mail arrives:
 *
 *   1. Suspicious      keyword match, any sender     -> label "Suspicious" (stays in inbox)
 *   2. Potential Scam  keyword match AND untrusted   -> label "Potential Scam", skip inbox, mark read
 *
 * "Trusted" = an address in Google Contacts (plus, optionally, people you have
 * emailed and Google's auto-saved "Other contacts"). Because a single Gmail
 * filter holds only ~1,500 characters, the trusted list is ranked by who most
 * recently emailed this account and packed until full. Anything left out is
 * reported by email.
 *
 * Required Advanced Services (Editor -> Services -> +):
 *   Gmail API   (identifier: Gmail)
 *   People API  (identifier: People)
 *
 * Entry points:
 *   previewTrustedList()  dry run: logs what would be built, changes nothing
 *   updateScamFilters()   builds or refreshes both filters (bind to a daily trigger)
 *   removeScamShield()    deletes both managed filters (labels are kept)
 */

const CONFIG = {
  // Phrases that mark a message as suspicious. Quoted as exact phrases.
  // Keep the list modest: it shares the filter's character budget.
  KEYWORDS: [
    'verify your account', 'verify your identity', 'account suspended',
    'account has been locked', 'unusual activity', 'suspicious activity',
    'confirm your identity', 'gift card', 'wire transfer', 'bitcoin',
    'urgent action required', 'act now', 'final notice', 'your refund',
    'social security', 'IRS', 'package undeliverable', 'delivery failed',
    'payment failed', 'update your payment', 'won a prize', 'claim your prize',
    'Geek Squad', 'renewal', 'invoice attached', 'tech support',
  ],

  SUSPICIOUS_LABEL: 'Suspicious',
  SCAM_LABEL: 'Potential Scam',

  // Trust sources beyond Google Contacts.
  INCLUDE_SENT_RECIPIENTS: true,   // people this account has emailed
  INCLUDE_OTHER_CONTACTS: false,   // Google's auto-saved contacts (broader, noisier)

  SENT_LOOKBACK: '2y',
  SENT_MAX_THREADS: 500,
  INBOUND_LOOKBACK: '2y',          // used only to rank trusted senders by recency
  INBOUND_MAX_THREADS: 1500,

  // Character budget for the trusted-sender part of the scam filter.
  // The script shrinks this automatically if Gmail rejects the filter.
  TRUSTED_QUERY_MAX_CHARS: 1400,

  // Your own address: receives failure notices and "contacts left out" reports.
  ALERT_EMAIL: '',
};

const PROP = {
  SUSPICIOUS_ID: 'suspiciousFilterId',
  SUSPICIOUS_SIG: 'suspiciousFilterSig',
  SCAM_ID: 'scamFilterId',
  SCAM_SIG: 'scamFilterSig',
  LAST_EXCLUDED: 'lastExcludedCount',
};

const EMAIL_RE = /[a-z0-9._%+'-]+@[a-z0-9.-]+\.[a-z]{2,}/gi;

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

function updateScamFilters() {
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(30000)) return;
  try {
    const plan = buildPlan_();
    const props = PropertiesService.getScriptProperties();
    const suspiciousLabelId = getOrCreateLabelId_(CONFIG.SUSPICIOUS_LABEL);
    const scamLabelId = getOrCreateLabelId_(CONFIG.SCAM_LABEL);

    // Filter 1: keywords -> Suspicious (any sender)
    ensureFilter_(PROP.SUSPICIOUS_ID, PROP.SUSPICIOUS_SIG, {
      criteria: { query: plan.keywordQuery },
      action: { addLabelIds: [suspiciousLabelId] },
    });

    // Filter 2: keywords AND NOT trusted -> Potential Scam, out of inbox, read
    const result = ensureScamFilterWithRetry_(plan, scamLabelId);

    const summary =
      `Trusted addresses found: ${plan.ranked.length}\n` +
      `Included in filter: ${result.included}\n` +
      `Left out (filter full): ${plan.ranked.length - result.included}\n` +
      `Trusted-list length: ${result.chars} chars`;
    console.log(summary);

    const excluded = plan.ranked.length - result.included;
    const lastExcluded = Number(props.getProperty(PROP.LAST_EXCLUDED) || 0);
    if (excluded > 0 && excluded !== lastExcluded) {
      const leftOut = plan.ranked.slice(result.included);
      notify_('Scam Shield: some contacts did not fit in the filter',
        summary + '\n\nNot currently trusted (least recently heard from):\n' +
        leftOut.join('\n') +
        '\n\nMail from these senders that contains a keyword will be quarantined.');
    }
    props.setProperty(PROP.LAST_EXCLUDED, String(excluded));
  } catch (err) {
    console.error(err);
    notify_('Scam Shield: update FAILED', String(err && err.stack || err));
    throw err;
  } finally {
    lock.releaseLock();
  }
}

function previewTrustedList() {
  const plan = buildPlan_();
  const packed = packAddresses_(plan.ranked, CONFIG.TRUSTED_QUERY_MAX_CHARS);
  console.log(`Keyword query (${plan.keywordQuery.length} chars):\n${plan.keywordQuery}`);
  console.log(`Trusted addresses found: ${plan.ranked.length}`);
  console.log(`Would include: ${packed.count} (${packed.query.length} chars)`);
  console.log(`Would leave out: ${plan.ranked.length - packed.count}`);
  console.log('Included, most recent sender first:\n' + plan.ranked.slice(0, packed.count).join('\n'));
  if (packed.count < plan.ranked.length) {
    console.log('Left out:\n' + plan.ranked.slice(packed.count).join('\n'));
  }
}

function removeScamShield() {
  const props = PropertiesService.getScriptProperties();
  [PROP.SUSPICIOUS_ID, PROP.SCAM_ID].forEach(key => {
    const id = props.getProperty(key);
    if (id) {
      try { Gmail.Users.Settings.Filters.remove('me', id); } catch (e) { /* already gone */ }
    }
  });
  props.deleteAllProperties();
  console.log('Both managed filters removed. Labels and their messages were left alone.');
}

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

function buildPlan_() {
  const mine = getMyAddresses_();

  const trusted = getContactEmails_();
  if (CONFIG.INCLUDE_OTHER_CONTACTS) getOtherContactEmails_().forEach(a => trusted.add(a));
  if (CONFIG.INCLUDE_SENT_RECIPIENTS) getSentRecipients_(mine).forEach(a => trusted.add(a));

  // Never trust this account's own address: "from yourself" spoofs are a common scam.
  mine.forEach(a => trusted.delete(a));

  const recency = getInboundRecency_(mine);
  const ranked = Array.from(trusted).sort((a, b) =>
    (recency.get(b) || 0) - (recency.get(a) || 0) || a.localeCompare(b));

  const keywordQuery = CONFIG.KEYWORDS
    .map(k => `"${k.replace(/"/g, '')}"`)
    .join(' OR ');

  return { ranked, keywordQuery };
}

function getMyAddresses_() {
  const mine = new Set([Session.getEffectiveUser().getEmail().toLowerCase()]);
  GmailApp.getAliases().forEach(a => mine.add(a.toLowerCase()));
  return mine;
}

function getContactEmails_() {
  const out = new Set();
  let pageToken;
  do {
    const resp = People.People.Connections.list('people/me', {
      personFields: 'emailAddresses',
      pageSize: 1000,
      pageToken: pageToken,
    });
    (resp.connections || []).forEach(p =>
      (p.emailAddresses || []).forEach(e => e.value && out.add(e.value.trim().toLowerCase())));
    pageToken = resp.nextPageToken;
  } while (pageToken);
  return out;
}

function getOtherContactEmails_() {
  const out = new Set();
  let pageToken;
  do {
    const resp = People.OtherContacts.list({
      readMask: 'emailAddresses',
      pageSize: 1000,
      pageToken: pageToken,
    });
    (resp.otherContacts || []).forEach(p =>
      (p.emailAddresses || []).forEach(e => e.value && out.add(e.value.trim().toLowerCase())));
    pageToken = resp.nextPageToken;
  } while (pageToken);
  return out;
}

function getSentRecipients_(mine) {
  const out = new Set();
  const query = `in:sent newer_than:${CONFIG.SENT_LOOKBACK}`;
  for (let start = 0; start < CONFIG.SENT_MAX_THREADS; start += 100) {
    const threads = GmailApp.search(query, start, 100);
    if (!threads.length) break;
    GmailApp.getMessagesForThreads(threads).forEach(msgs => msgs.forEach(m => {
      const from = extract_(m.getFrom())[0];
      if (!from || !mine.has(from)) return; // only messages this account sent
      extract_([m.getTo(), m.getCc(), m.getBcc()].join(',')).forEach(a => out.add(a));
    }));
  }
  return out;
}

function getInboundRecency_(mine) {
  const seen = new Map();
  const query = `newer_than:${CONFIG.INBOUND_LOOKBACK} -from:me`;
  for (let start = 0; start < CONFIG.INBOUND_MAX_THREADS; start += 100) {
    const threads = GmailApp.search(query, start, 100);
    if (!threads.length) break;
    GmailApp.getMessagesForThreads(threads).forEach(msgs => msgs.forEach(m => {
      const from = extract_(m.getFrom())[0];
      if (!from || mine.has(from)) return;
      const t = m.getDate().getTime();
      if (t > (seen.get(from) || 0)) seen.set(from, t);
    }));
  }
  return seen;
}

function extract_(text) {
  return ((text || '').match(EMAIL_RE) || []).map(a => a.toLowerCase());
}

// Packs addresses into from:{a b c} until the character budget is reached.
function packAddresses_(ranked, maxChars) {
  const parts = [];
  let length = 'from:{}'.length;
  for (const addr of ranked) {
    const add = addr.length + (parts.length ? 1 : 0);
    if (length + add > maxChars) break;
    parts.push(addr);
    length += add;
  }
  return { query: parts.length ? `from:{${parts.join(' ')}}` : '', count: parts.length };
}

// ---------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------

function ensureScamFilterWithRetry_(plan, scamLabelId) {
  let budget = CONFIG.TRUSTED_QUERY_MAX_CHARS;
  for (let attempt = 1; attempt <= 5; attempt++) {
    const packed = packAddresses_(plan.ranked, budget);
    const criteria = { query: plan.keywordQuery };
    if (packed.query) criteria.negatedQuery = packed.query;
    try {
      ensureFilter_(PROP.SCAM_ID, PROP.SCAM_SIG, {
        criteria: criteria,
        action: { addLabelIds: [scamLabelId], removeLabelIds: ['INBOX', 'UNREAD'] },
      });
      return { included: packed.count, chars: packed.query.length };
    } catch (err) {
      console.warn(`Attempt ${attempt} rejected at ${budget} chars: ${err}`);
      budget = Math.floor(budget * 0.8);
    }
  }
  throw new Error('Gmail rejected the scam filter at every size tried. The existing filter, if any, was left in place.');
}

// Creates the new filter before deleting the old one, so protection never lapses.
// Skips the update entirely when nothing has changed and the filter still exists.
function ensureFilter_(idKey, sigKey, body) {
  const props = PropertiesService.getScriptProperties();
  const sig = JSON.stringify(body);
  const oldId = props.getProperty(idKey);

  if (oldId && props.getProperty(sigKey) === sig && filterExists_(oldId)) return oldId;

  const created = Gmail.Users.Settings.Filters.create(body, 'me');
  props.setProperty(idKey, created.id);
  props.setProperty(sigKey, sig);

  if (oldId && oldId !== created.id) {
    try { Gmail.Users.Settings.Filters.remove('me', oldId); } catch (e) { /* already gone */ }
  }
  return created.id;
}

function filterExists_(id) {
  try { Gmail.Users.Settings.Filters.get('me', id); return true; } catch (e) { return false; }
}

function getOrCreateLabelId_(name) {
  const labels = Gmail.Users.Labels.list('me').labels || [];
  const existing = labels.find(l => l.name === name);
  if (existing) return existing.id;
  return Gmail.Users.Labels.create({
    name: name,
    labelListVisibility: 'labelShow',
    messageListVisibility: 'show',
  }, 'me').id;
}

function notify_(subject, body) {
  if (!CONFIG.ALERT_EMAIL) return;
  MailApp.sendEmail(CONFIG.ALERT_EMAIL, subject, body);
}
