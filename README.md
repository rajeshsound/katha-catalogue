# Katha Catalogue & Rights

A complete catalogue and copyright management system for Katha Books.
One small web app, no servers, no subscriptions, no software company required.

## What it does

- **Catalogue** — all titles with search and filters across language, category, status
- **Rights & royalty** — copyright holder, rights type, territory, expiry alerts,
  CC/Wikimedia licence flags, royalty entitlements (rates, base, advances)
- **Generate catalogue** — searchable filters across Themes, Series, Big ideas,
  Grades, Subjects, Skills, SPICE, SDGs and CBSE frameworks, plus a
  search-everything box. Choose what each entry includes: cover image, summary
  (catalog summary or full story description), price, ISBN, contributors,
  pedagogy line, and pages/size/weight. Print, save as PDF, or export a
  standalone HTML page
- **Import** — reads Katha's existing Excel files directly, including the
  Master Backlist 2026 Enriched format (Themes/Keywords, Big Idea, Subjects,
  Skills, SPICE, Grade/Class, Age Group, Reading Level, ViBGYOR, dimensions,
  weight, pages, Catalog Summary, Story Description, Portal Link, SDGs
  Addressed, How It Addresses the SDGs, CBSE Frameworks, How CBSE Frameworks
  Connect). Recognises your real
  column headings (Title, Lang, Author, Illustrator, Availability, Price,
  ISBN No., Pdf Link…), finds the header row automatically, extracts real
  SharePoint URLs from PDF link cells, and de-duplicates across sheets
- **Export** — three-sheet Excel workbook (Catalogue / Rights / Royalty) for
  selective sharing, plus a full JSON backup
- **Automatic flags** — any title with "Wikimedia Commons" as illustrator is
  flagged "CC — needs checking" until the licence type is recorded

## Deploy to GitHub Pages (one time, ~5 minutes)

1. Go to github.com → New repository → name it `katha-catalogue` → Public → Create
2. Click "uploading an existing file" and drag in these three files:
   `index.html`, `app.js`, `manifest.json`
3. Commit the files
4. Repository Settings → Pages → Source: "Deploy from a branch" →
   Branch: `main`, folder `/ (root)` → Save
5. After a minute your app is live at
   `https://YOUR-USERNAME.github.io/katha-catalogue/`

### Install on phones and tablets
Open the URL in Safari (iPhone/iPad) or Chrome (Android) →
Share → **Add to Home Screen**. It opens full-screen like an app.
Your data lives in the browser's local storage and stays on the device;
the app loads fresh from GitHub each time it is opened (online).

### Updating the app later
When you upload a new `app.js` or `index.html` to GitHub, edit one line
in `index.html` and bump the version date so browsers fetch the new code
instead of a stale copy:

```html
<script src="app.js?v=2026-06-18"></script>
```

Change `2026-06-18` to the new date each time you deploy a change.
That is the only step needed — there is no service worker or offline
cache to clear anymore.

## First-time setup

1. Open the app → **Data & backup** → Import your
   `Katha Book details 441 titles.xlsx` file
2. Then import `Katha All Book Master PDFs Link.xlsx` — this adds the
   Kannada and Tamil titles, English title mappings, ISBNs and PDF links
3. Check the **Dashboard** — it will list everything needing attention
   (CC licences to verify, missing blurbs, missing rights data)
4. Export a **JSON backup** immediately and store it in SharePoint

## Daily use

- Click any row to open the title drawer: Bibliographic / Rights / Royalty tabs
- SKUs are generated automatically on first save (KTH-LANG-CAT-AGE-FMT-SEQ-YEAR)
- Changing an MRP automatically appends to the price history — never overwritten
- The Rights view sorts by expiry; the filter finds CC titles or missing records
- Generate catalogue: pick filters → preview updates live → Print / save PDF
  (use the browser's print dialog and choose "Save as PDF")

## Important: how data is stored

All data lives **in the browser of the device you use** (IndexedDB).
Nothing is sent anywhere. This means:

- **Back up weekly**: Data & backup → Full backup (.json) → save to SharePoint
- **Moving to another device**: export the JSON backup on one device,
  restore it on the other
- **One person should be the "keeper"** of the master data. Others can
  hold read copies, but edits should happen on the keeper's device, with
  the JSON backup as the handover file

### When the team needs simultaneous editing
This app is the working foundation and the catalogue generator. When several
people need to edit at the same time from different places, that is the moment
to move the data into Airtable (the Phase 1 plan) or a small Supabase backend —
the Excel export from this app imports into either without rework. The screens
and workflows stay the same.

## Royalty boundary

Royalty figures here are **entitlements** (what is owed per contract).
Actual payments, TDS and GST remain in Tally / Zoho Books. The Royalty sheet
in the Excel export is what you hand to accounts.

## Files

| File | Purpose |
|---|---|
| `index.html` | The whole interface |
| `app.js` | All logic — storage, import/export, rights flags, generator |
| `manifest.json` | Makes it installable as an app |
