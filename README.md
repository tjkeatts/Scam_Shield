# Scam Shield for Gmail

A Google Apps Script that quarantines likely scam email the instant it arrives, using two Gmail filters it rebuilds nightly from the account's Google Contacts. Built for a family member who reads mail on iPhone and iPad: nothing is installed on the devices, because the filters live in Gmail on Google's servers.

## How it works

Two Gmail filters act at delivery time, so a likely scam never appears in the inbox or triggers a notification. A nightly script rebuilds them; nothing runs at delivery time except Gmail itself.

| Incoming mail | Has a keyword | No keyword |
| --- | --- | --- |
| **Trusted sender** | Inbox, labelled *Suspicious* | Inbox, untouched |
| **Unknown sender** | Labelled *Potential Scam*, skips inbox, marked read | Inbox, untouched |

- **Trusted** means an address in Google Contacts, plus anyone the account has emailed in the last two years. Google's auto-saved "Other contacts" can be switched on in `CONFIG`.
- **The cap:** one Gmail filter holds about 1,500 characters, roughly 50–60 addresses. The script ranks trusted addresses by who most recently emailed the account and packs the filter until full. Anyone left out is emailed to `ALERT_EMAIL`.
- **The script owns both filters.** Edit keywords in the script, never in Gmail settings; the next run overwrites manual changes.
- Gmail filters cannot chain (a filter can't act on a label another filter applied), which is why the whole trusted list must fit in one filter.

## Files

| File | Purpose |
| --- | --- |
| `scam-shield.gs` | The Apps Script. Paste into a project at script.google.com. |
| `README.md` | This setup runbook. |

## Before you start

Install from a computer, signed into **their** Google account.

- [ ] Their agreement: the script reads their contacts and mail headers and runs as them.
- [ ] Their password, and their phone nearby for the two-step prompt.
- [ ] A separate Chrome profile (or a private window) for their account, so it never mixes with yours.
- [ ] Remove anything from earlier attempts: any hand-made *Suspicious* or scam filter (Gmail → Settings → See all settings → Filters and Blocked Addresses) and any earlier Apps Script project. Leave the labels; the script reuses them.

## Install

1. In their Chrome profile, go to script.google.com → **New project**. Rename it *Scam Shield*.
2. Left sidebar → **Services** → **+**. Add **Gmail API** and keep the identifier `Gmail`. Repeat for **People API**, identifier `People`. The code calls these exact names.
3. Select everything in `Code.gs`, delete it, and paste the full contents of `scam-shield.gs`. Save (⌘S).
4. Edit `CONFIG` at the top:
   - `ALERT_EMAIL`: your own address. Failure notices and "contacts left out" reports come to you, not to them.
   - `KEYWORDS`: your phrases. Shorter lists leave more room for trusted senders, since both share one filter.
   - Leave the rest at defaults for the first run.

## First run

Run the dry run first; it reads everything and changes nothing.

1. In the toolbar's function dropdown pick `previewTrustedList` → **Run**.
2. Authorize: **Review permissions** → choose their account → "Google hasn't verified this app" → **Advanced** → **Go to Scam Shield (unsafe)** → **Allow**. The warning is expected; it is their own script, not a published app. It asks to read contacts, read and modify Gmail, manage Gmail filters and send email as them (the last is only for alerts to you).
3. Read the **Execution log**:
   - *Trusted addresses found* versus *Would include*. If any are left out, the bottom of the list is whoever has emailed least recently.
   - Spot-check that the family addresses you'd expect appear in the included list.
4. Pick `updateScamFilters` → **Run**. The log should end with the included count and the list length in characters.
5. Confirm in Gmail on the web: Settings → **Filters and Blocked Addresses** shows two new filters, one labelling *Suspicious* and one labelling *Potential Scam* that skips the inbox. Don't edit them by hand.

## Schedule

1. Left sidebar → **Triggers** (clock icon) → **Add Trigger**.
2. Function `updateScamFilters`, event source **Time-driven**, **Day timer**, 2am–3am.
3. Failure notification: **Notify me daily**. Google sends these to the script owner (them), so `ALERT_EMAIL` is what actually reaches you.

After adding a contact you want trusted immediately, run `updateScamFilters` by hand. A run with no changes leaves the filters untouched.

## Test

Put one of your keywords (say, "gift card") in each test email.

| Send from | Expected result |
| --- | --- |
| An address not in their contacts | No notification; message appears only under the *Potential Scam* label, already read |
| Your own address, which is in their contacts | Normal notification; in the inbox with the *Suspicious* label |

In the Gmail app the labels sit in the side menu. In Apple Mail they appear as folders; quarantined mail sits in *Potential Scam* and "All Mail", never the Inbox, so neither app notifies for it.

## Weekly routine

1. Open the *Potential Scam* label.
2. For a legitimate message: move it to the Inbox.
3. Add the sender to **Google** Contacts. contacts.google.com is the surest route. The iPad Contacts app works only if the Google account syncs contacts (Settings → Apps → Contacts → Accounts → Gmail → Contacts on) and the contact is saved to that account rather than iCloud.
4. Run `updateScamFilters` by hand, or let the nightly run pick it up.
5. If a "contacts left out" email arrives, prune the keyword list or remove stale contacts until the important ones fit.

## Limitations

This is a keyword net with a guest list, not a scam detector; Gmail's own spam filtering still does the heavy lifting.

- **Keywords only.** A scam using none of your phrases passes through.
- **Display-name spoofing.** Gmail's `from:` search also matches the sender's display name, so a stranger who sets their name to a trusted address can slip past the quarantine.
- **Compromised contacts.** Mail from a hijacked friend's real account is trusted.
- **New contacts lag.** A sender is trusted only from the next run after they're added.
- **The cap.** Around 50–60 trusted addresses; the overflow email says who's out.
- **The account's own address is never trusted**, because "from yourself" extortion emails are a common scam.

## Uninstall

Run `removeScamShield` (deletes both filters, keeps the labels and their mail), delete the trigger, then delete the project.
