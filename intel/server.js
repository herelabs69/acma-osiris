/**
 * OSIRIS Intelligence Layer — osiris-intel
 *
 * Centralized ontology engine that ingests, indexes, and correlates entities
 * across open-source intelligence feeds. All other services query this one
 * brain via GET /resolve.
 *
 * Data sources:
 *   - OpenSanctions (OFAC SDN) — bulk CSV, refreshed every 24h
 *   - Wikidata SPARQL — on-demand with aggressive LRU cache
 *
 * Security:
 *   - Outbound requests only to allowlisted domains
 *   - SPARQL inputs sanitized against injection
 *   - Rate-limited per client IP
 */

const express = require('express');
const app = express();
// รองรับทั้ง PORT (มาตรฐานของ Render/Railway/Heroku ฯลฯ) และ INTEL_PORT (ใช้เดิมใน Docker)
const PORT = process.env.PORT || process.env.INTEL_PORT || 4000;

// ════════════════════════════════════════════════════
// §1 — CONFIGURATION
// ════════════════════════════════════════════════════

const SDN_CSV_URL = 'https://data.opensanctions.org/datasets/latest/us_ofac_sdn/targets.simple.csv';
const WIKIDATA_ENDPOINT = 'https://query.wikidata.org/sparql';
const WIKIDATA_UA = 'OSIRIS-Intel/1.0 (https://osirisai.live; ontology engine)';
const SDN_REFRESH_MS = 24 * 60 * 60 * 1000; // 24h
const WIKIDATA_CACHE_TTL = 24 * 60 * 60 * 1000; // 24h
const WIKIDATA_CACHE_MAX = 10_000;

const ALLOWED_DOMAINS = new Set(['query.wikidata.org', 'data.opensanctions.org', 'www.wikidata.org', 'ip-api.com', 'stat.ripe.net', 'api.planespotters.net']);

// ════════════════════════════════════════════════════
// §2 — SANCTIONS INDEX (in-memory graph)
// ════════════════════════════════════════════════════

let sanctionsIndex = {
  entries: [],
  byNorm: new Map(),   // normalised name/alias → [entry]
  fetchedAt: 0,
};

function normName(s) {
  return s.toLowerCase().replace(/[^\p{L}\p{N}\s]+/gu, ' ').replace(/\s+/g, ' ').trim();
}

function parseCsv(text) {
  const rows = [];
  let field = '', row = [], inQ = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQ) {
      if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else inQ = false; }
      else field += c;
    } else if (c === '"') inQ = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; }
    else if (c !== '\r') field += c;
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  return rows;
}

async function loadSanctions() {
  console.log('[INTEL] Loading OpenSanctions OFAC SDN...');
  try {
    const res = await fetch(SDN_CSV_URL, {
      signal: AbortSignal.timeout(30000),
      headers: { Accept: 'text/csv' },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    const rows = parseCsv(text);
    if (rows.length < 2) throw new Error('CSV empty');

    const headers = rows[0];
    const idx = (col) => headers.indexOf(col);
    const i = {
      id: idx('id'), schema: idx('schema'), name: idx('name'),
      aliases: idx('aliases'), countries: idx('countries'),
      programs: idx('program_ids'), sanctions: idx('sanctions'),
      first_seen: idx('first_seen'), last_seen: idx('last_seen'),
    };

    const entries = [];
    const byNorm = new Map();

    for (let r = 1; r < rows.length; r++) {
      const row = rows[r];
      if (!row[i.name]) continue;
      const entry = {
        id: row[i.id] || '',
        schema: row[i.schema] || 'LegalEntity',
        name: row[i.name],
        aliases: (row[i.aliases] || '').split(';').map(s => s.trim()).filter(Boolean),
        countries: (row[i.countries] || '').split(';').map(s => s.trim()).filter(Boolean),
        programs: (row[i.programs] || '').split(';').map(s => s.trim()).filter(Boolean),
        sanctions: row[i.sanctions] || '',
        first_seen: i.first_seen >= 0 ? row[i.first_seen] : undefined,
      };
      entries.push(entry);

      const keys = new Set([entry.name, ...entry.aliases].map(normName));
      for (const key of keys) {
        if (!key) continue;
        if (!byNorm.has(key)) byNorm.set(key, []);
        byNorm.get(key).push(entry);
      }
    }

    sanctionsIndex = { entries, byNorm, fetchedAt: Date.now() };
    console.log(`[INTEL] Sanctions index loaded: ${entries.length} entities, ${byNorm.size} name keys`);
  } catch (e) {
    console.error('[INTEL] Sanctions load failed:', e.message);
    if (sanctionsIndex.entries.length > 0) {
      console.log('[INTEL] Keeping stale index');
    }
  }
}

function sanctionsSearch(query, limit = 5) {
  if (!query || query.length < 3) return [];
  const q = normName(query);
  const exact = sanctionsIndex.byNorm.get(q) || [];
  if (exact.length > 0) return exact.slice(0, limit);

  const results = [];
  const seen = new Set();
  for (const entry of sanctionsIndex.entries) {
    if (results.length >= limit) break;
    if (seen.has(entry.id)) continue;
    const n = normName(entry.name);
    if (n.includes(q) || entry.aliases.some(a => normName(a).includes(q))) {
      seen.add(entry.id);
      results.push(entry);
    }
  }
  return results;
}

// ════════════════════════════════════════════════════
// §3 — WIKIDATA LRU CACHE
// ════════════════════════════════════════════════════

const wdCache = new Map(); // key → { data, ts }

function wdCacheGet(key) {
  const entry = wdCache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.ts > WIKIDATA_CACHE_TTL) { wdCache.delete(key); return null; }
  // Move to end (LRU)
  wdCache.delete(key);
  wdCache.set(key, entry);
  return entry.data;
}

function wdCacheSet(key, data) {
  if (wdCache.size >= WIKIDATA_CACHE_MAX) {
    const oldest = wdCache.keys().next().value;
    wdCache.delete(oldest);
  }
  wdCache.set(key, { data, ts: Date.now() });
}

// ════════════════════════════════════════════════════
// §4 — WIKIDATA SPARQL (safe)
// ════════════════════════════════════════════════════

function sanitizeId(id) {
  return id.replace(/[^a-zA-Z0-9 \-._]/g, '').trim();
}

async function sparql(query) {
  const url = `${WIKIDATA_ENDPOINT}?query=${encodeURIComponent(query)}&format=json`;
  const parsed = new URL(url);
  if (!ALLOWED_DOMAINS.has(parsed.hostname)) {
    throw new Error(`Blocked domain: ${parsed.hostname}`);
  }
  const res = await fetch(url, {
    headers: { 'User-Agent': WIKIDATA_UA, Accept: 'application/sparql-results+json' },
    signal: AbortSignal.timeout(10000),
  });
  if (!res.ok) return [];
  const json = await res.json();
  return json.results?.bindings || [];
}

// Search Wikidata for an entity by name, returns QID or null
async function wdSearch(query, type = 'item') {
  const url = `https://www.wikidata.org/w/api.php?action=wbsearchentities&search=${encodeURIComponent(query)}&language=en&limit=1&format=json`;
  const parsed = new URL(url);
  if (!ALLOWED_DOMAINS.has(parsed.hostname)) return null;
  try {
    const res = await fetch(url, {
      headers: { 'User-Agent': WIKIDATA_UA },
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return null;
    const json = await res.json();
    return json.search?.[0]?.id || null;
  } catch { return null; }
}

// ════════════════════════════════════════════════════
// §5 — RESOLVERS (the intelligence)
// ════════════════════════════════════════════════════

function addSanctionsToGraph(query, rootId, nodes, links) {
  const matches = sanctionsSearch(query);
  for (const m of matches) {
    const sid = `sanction:${m.id}`;
    nodes.push({
      id: sid, label: `⚠ ${m.name}`, type: 'sanction',
      properties: {
        schema: m.schema, countries: m.countries.join(', '),
        programs: m.programs.join(', '), sanctions: m.sanctions,
        aliases: m.aliases.slice(0, 5).join('; '),
        first_seen: m.first_seen, sanctioned: true,
      },
    });
    links.push({ source: rootId, target: sid, label: 'SANCTIONS MATCH' });
  }
}

function dedup(nodes, links) {
  const seen = new Set();
  const uNodes = [];
  for (const n of nodes) { if (!seen.has(n.id)) { seen.add(n.id); uNodes.push(n); } }
  const lSeen = new Set();
  const uLinks = [];
  for (const l of links) {
    const k = `${l.source}→${l.target}→${l.label}`;
    if (!lSeen.has(k)) { lSeen.add(k); uLinks.push(l); }
  }
  return { nodes: uNodes, links: uLinks };
}

// ── ดึงรูปถ่ายเครื่องบินจาก Planespotters (ฟรี ไม่ต้องใช้ key) ──
// ค้นจาก ICAO24 (hex) ก่อน ถ้าไม่มีค่อยลองทะเบียน
async function fetchAircraftPhoto(icao24, registration) {
  const tryUrl = async (url) => {
    const parsed = new URL(url);
    if (!ALLOWED_DOMAINS.has(parsed.hostname)) return null;
    try {
      const res = await fetch(url, {
        headers: { Accept: 'application/json', 'User-Agent': WIKIDATA_UA },
        signal: AbortSignal.timeout(6000),
      });
      if (!res.ok) return null;
      const json = await res.json();
      const p = json?.photos?.[0];
      if (!p) return null;
      return {
        thumbnail: p.thumbnail_large?.src || p.thumbnail?.src || null,
        link: p.link || null,
        photographer: p.photographer || null,
      };
    } catch { return null; }
  };
  let photo = null;
  if (icao24) photo = await tryUrl(`https://api.planespotters.net/pub/photos/hex/${encodeURIComponent(icao24.toLowerCase())}`);
  if (!photo && registration) photo = await tryUrl(`https://api.planespotters.net/pub/photos/reg/${encodeURIComponent(registration.toUpperCase())}`);
  return photo;
}

// ── สเปกพื้นฐานตามรหัสรุ่นเครื่องบิน (ICAO type) — ข้อมูลคงที่ ไม่ต้องเรียก API ──
const AIRCRAFT_SPECS = {
  // Boeing
  B738: { name: 'Boeing 737-800', engines: '2 × CFM56-7B', seats: '162–189', range_km: 5765, manufacturer: 'Boeing' },
  B739: { name: 'Boeing 737-900', engines: '2 × CFM56-7B', seats: '178–220', range_km: 5925, manufacturer: 'Boeing' },
  B38M: { name: 'Boeing 737 MAX 8', engines: '2 × CFM LEAP-1B', seats: '162–210', range_km: 6570, manufacturer: 'Boeing' },
  B752: { name: 'Boeing 757-200', engines: '2 × RB211 / PW2000', seats: '200', range_km: 7250, manufacturer: 'Boeing' },
  B763: { name: 'Boeing 767-300', engines: '2 × CF6 / PW4000', seats: '218–269', range_km: 11070, manufacturer: 'Boeing' },
  B772: { name: 'Boeing 777-200', engines: '2 × GE90 / Trent 800', seats: '314–440', range_km: 13080, manufacturer: 'Boeing' },
  B77W: { name: 'Boeing 777-300ER', engines: '2 × GE90-115B', seats: '365–550', range_km: 13650, manufacturer: 'Boeing' },
  B788: { name: 'Boeing 787-8 Dreamliner', engines: '2 × GEnx / Trent 1000', seats: '242–359', range_km: 13530, manufacturer: 'Boeing' },
  B789: { name: 'Boeing 787-9 Dreamliner', engines: '2 × GEnx / Trent 1000', seats: '290–406', range_km: 14140, manufacturer: 'Boeing' },
  B744: { name: 'Boeing 747-400', engines: '4 × CF6 / PW4000 / RB211', seats: '416–660', range_km: 13450, manufacturer: 'Boeing' },
  // Airbus
  A319: { name: 'Airbus A319', engines: '2 × CFM56 / V2500', seats: '124–156', range_km: 6850, manufacturer: 'Airbus' },
  A320: { name: 'Airbus A320', engines: '2 × CFM56 / V2500', seats: '150–186', range_km: 6100, manufacturer: 'Airbus' },
  A20N: { name: 'Airbus A320neo', engines: '2 × LEAP-1A / PW1100G', seats: '150–194', range_km: 6500, manufacturer: 'Airbus' },
  A321: { name: 'Airbus A321', engines: '2 × CFM56 / V2500', seats: '185–236', range_km: 5950, manufacturer: 'Airbus' },
  A21N: { name: 'Airbus A321neo', engines: '2 × LEAP-1A / PW1100G', seats: '180–244', range_km: 7400, manufacturer: 'Airbus' },
  A332: { name: 'Airbus A330-200', engines: '2 × Trent 700 / CF6 / PW4000', seats: '210–406', range_km: 13450, manufacturer: 'Airbus' },
  A333: { name: 'Airbus A330-300', engines: '2 × Trent 700 / CF6 / PW4000', seats: '250–440', range_km: 11750, manufacturer: 'Airbus' },
  A359: { name: 'Airbus A350-900', engines: '2 × Trent XWB', seats: '300–440', range_km: 15000, manufacturer: 'Airbus' },
  A35K: { name: 'Airbus A350-1000', engines: '2 × Trent XWB-97', seats: '350–480', range_km: 16100, manufacturer: 'Airbus' },
  A388: { name: 'Airbus A380-800', engines: '4 × Trent 900 / GP7000', seats: '525–853', range_km: 14800, manufacturer: 'Airbus' },
  // Regional / others
  E190: { name: 'Embraer E190', engines: '2 × GE CF34', seats: '96–114', range_km: 4500, manufacturer: 'Embraer' },
  E75L: { name: 'Embraer E175', engines: '2 × GE CF34', seats: '76–88', range_km: 3900, manufacturer: 'Embraer' },
  AT76: { name: 'ATR 72-600', engines: '2 × PW127', seats: '70–78', range_km: 1500, manufacturer: 'ATR' },
  DH8D: { name: 'Bombardier Dash 8 Q400', engines: '2 × PW150A', seats: '78–90', range_km: 2040, manufacturer: 'Bombardier' },
  BCS3: { name: 'Airbus A220-300', engines: '2 × PW1500G', seats: '120–160', range_km: 6700, manufacturer: 'Airbus' },
};

async function resolveAircraft(id, properties = {}) {
  const rootId = `aircraft:${id}`;
  const nodes = [], links = [];
  const cacheKey = `aircraft:${id}:${properties.registration || ''}`;
  const cached = wdCacheGet(cacheKey);
  if (cached) return { ...cached };

  const callsign = id.toUpperCase().trim();
  const registration = (properties.registration || '').toUpperCase().trim();
  const model = properties.model || '';

  // Step 1: Decode ICAO airline prefix from callsign (e.g. TRK → Turkish Airlines)
  // The prefix is the alphabetic portion of the callsign
  const airlinePrefix = callsign.replace(/[0-9]+$/, '');
  let airlineName = null;

  if (airlinePrefix && airlinePrefix.length >= 2) {
    // Search Wikidata for the ICAO airline code
    try {
      const results = await sparql(`
        SELECT ?item ?itemLabel ?countryLabel ?ceoLabel ?parentLabel WHERE {
          ?item wdt:P230 "${airlinePrefix}" .
          OPTIONAL { ?item wdt:P17 ?country . }
          OPTIONAL { ?item wdt:P169 ?ceo . }
          OPTIONAL { ?item wdt:P749 ?parent . }
          SERVICE wikibase:label { bd:serviceParam wikibase:language "en" . }
        } LIMIT 5`);

      for (const r of results) {
        if (r.itemLabel?.value) {
          airlineName = r.itemLabel.value;
          const airId = `company:${airlineName}`;
          nodes.push({ id: airId, label: airlineName, type: 'company', properties: { icao_code: airlinePrefix, source: 'Wikidata' } });
          links.push({ source: rootId, target: airId, label: 'OPERATED BY' });

          if (r.countryLabel?.value) {
            const cid = `country:${r.countryLabel.value}`;
            nodes.push({ id: cid, label: r.countryLabel.value, type: 'country', properties: { source: 'Wikidata' } });
            links.push({ source: airId, target: cid, label: 'HEADQUARTERED' });
          }
          if (r.ceoLabel?.value) {
            const pid = `person:${r.ceoLabel.value}`;
            nodes.push({ id: pid, label: r.ceoLabel.value, type: 'person', properties: { role: 'CEO', source: 'Wikidata' } });
            links.push({ source: airId, target: pid, label: 'CEO' });
          }
          if (r.parentLabel?.value) {
            const pid = `company:${r.parentLabel.value}`;
            nodes.push({ id: pid, label: r.parentLabel.value, type: 'company', properties: { source: 'Wikidata' } });
            links.push({ source: airId, target: pid, label: 'PARENT ORG' });
          }
        }
      }
    } catch (e) { console.warn('[INTEL] Airline ICAO lookup error:', e.message); }
  }

  // Step 2: Decode registration prefix → country (e.g. TC → Turkey, N → USA, G → UK)
  const REG_PREFIXES = {
    'N':'United States','G':'United Kingdom','F':'France','D':'Germany','I':'Italy',
    'JA':'Japan','HL':'South Korea','B':'China','VT':'India','TC':'Turkey',
    'SU':'Russia','RA':'Russia','UR':'Ukraine','A6':'UAE','A7':'Qatar','9V':'Singapore',
    'VH':'Australia','C':'Canada','PP':'Brazil','PR':'Brazil','PT':'Brazil',
    'EC':'Spain','PH':'Philippines','HS':'Thailand','9M':'Malaysia','PK':'Pakistan',
    'EP':'Iran','YI':'Iraq','HZ':'Saudi Arabia','4X':'Israel','SX':'Greece',
    'OE':'Austria','HB':'Switzerland','SE':'Sweden','OH':'Finland','LN':'Norway',
    'OY':'Denmark','PH':'Netherlands','OO':'Belgium','CS':'Portugal','SP':'Poland',
    'OK':'Czech Republic','HA':'Hungary','YR':'Romania','LZ':'Bulgaria',
    'EI':'Ireland','EW':'Belarus','ES':'Estonia','YL':'Latvia','LY':'Lithuania',
  };

  if (registration) {
    let regCountry = null;
    // Try 2-char prefix first, then 1-char
    if (REG_PREFIXES[registration.substring(0, 2)]) regCountry = REG_PREFIXES[registration.substring(0, 2)];
    else if (REG_PREFIXES[registration.substring(0, 1)]) regCountry = REG_PREFIXES[registration.substring(0, 1)];

    if (regCountry) {
      const cid = `country:${regCountry}`;
      nodes.push({ id: cid, label: regCountry, type: 'country', properties: { source: 'Registration prefix' } });
      links.push({ source: rootId, target: cid, label: 'REGISTERED IN' });
    }
  }

  // Step 3: Add aircraft model info (พร้อมสเปกพื้นฐานถ้ารู้จักรุ่น)
  const spec = model ? AIRCRAFT_SPECS[model.toUpperCase()] : null;
  if (model) {
    const mid = `aircraft:model:${model}`;
    nodes.push({
      id: mid, label: spec ? spec.name : model, type: 'aircraft',
      properties: { type: 'model', source: 'ADS-B', ...(spec || {}) },
    });
    links.push({ source: rootId, target: mid, label: 'AIRCRAFT TYPE' });
  }

  // Step 4: Cross-ref sanctions on airline name + callsign
  addSanctionsToGraph(callsign, rootId, nodes, links);
  if (airlineName) addSanctionsToGraph(airlineName, rootId, nodes, links);
  if (registration) addSanctionsToGraph(registration, rootId, nodes, links);

  // Step 5: ดึงรูปถ่ายจริง + แนบ meta (รูป/สเปก) ไว้ที่ node ราก เพื่อให้ UI แสดงได้
  const icao24 = properties.icao24 || '';
  let photo = null;
  if (icao24 || registration) {
    photo = await fetchAircraftPhoto(icao24, registration);
  }
  const rootNode = nodes.find(n => n.id === rootId);
  if (rootNode) {
    rootNode.properties = { ...(rootNode.properties || {}), photo, spec: spec || null, icao24: icao24 || null };
  } else {
    nodes.unshift({ id: rootId, label: callsign, type: 'aircraft', properties: { photo, spec: spec || null, icao24: icao24 || null, registration, model } });
  }

  const result = dedup(nodes, links);
  wdCacheSet(cacheKey, result);
  return result;
}

async function resolveVessel(id) {
  const rootId = `vessel:${id}`;
  const nodes = [], links = [];
  const cached = wdCacheGet(`vessel:${id}`);
  if (cached) return { ...cached };

  try {
    const results = await sparql(`
      SELECT ?item ?itemLabel ?ownerLabel ?countryLabel ?operatorLabel ?flagLabel WHERE {
        { ?item wdt:P458 "${id}" . }
        UNION { ?item rdfs:label "${id}"@en . ?item wdt:P31/wdt:P279* wd:Q11446 . }
        OPTIONAL { ?item wdt:P127 ?owner . }
        OPTIONAL { ?item wdt:P17 ?country . }
        OPTIONAL { ?item wdt:P137 ?operator . }
        OPTIONAL { ?item wdt:P8047 ?flag . }
        SERVICE wikibase:label { bd:serviceParam wikibase:language "en" . }
      } LIMIT 10`);
    for (const r of results) {
      if (r.ownerLabel?.value) {
        const oid = `company:${r.ownerLabel.value}`;
        nodes.push({ id: oid, label: r.ownerLabel.value, type: 'company', properties: { source: 'Wikidata' } });
        links.push({ source: rootId, target: oid, label: 'OWNED BY' });
      }
      const flag = r.flagLabel?.value || r.countryLabel?.value;
      if (flag) {
        const cid = `country:${flag}`;
        nodes.push({ id: cid, label: flag, type: 'country', properties: { source: 'Wikidata' } });
        links.push({ source: rootId, target: cid, label: 'FLAG STATE' });
      }
      if (r.operatorLabel?.value) {
        const oid = `company:${r.operatorLabel.value}`;
        nodes.push({ id: oid, label: r.operatorLabel.value, type: 'company', properties: { source: 'Wikidata' } });
        links.push({ source: rootId, target: oid, label: 'OPERATED BY' });
      }
    }
  } catch (e) { console.warn('[INTEL] Wikidata vessel error:', e.message); }

  addSanctionsToGraph(id, rootId, nodes, links);
  const result = dedup(nodes, links);
  wdCacheSet(`vessel:${id}`, result);
  return result;
}

async function resolveCompany(id) {
  const rootId = `company:${id}`;
  const nodes = [], links = [];
  const cached = wdCacheGet(`company:${id}`);
  if (cached) return { ...cached };

  try {
    // Use Wikidata search to find the QID first, then resolve by QID
    const qid = await wdSearch(id);
    const filter = qid
      ? `VALUES ?item { wd:${qid} }`
      : `?item rdfs:label "${id}"@en . { ?item wdt:P31/wdt:P279* wd:Q4830453 . } UNION { ?item wdt:P31/wdt:P279* wd:Q43229 . }`;
    const results = await sparql(`
      SELECT ?item ?itemLabel ?countryLabel ?parentLabel ?ceoLabel ?industryLabel WHERE {
        ${filter}
        OPTIONAL { ?item wdt:P17 ?country . }
        OPTIONAL { ?item wdt:P749 ?parent . }
        OPTIONAL { ?item wdt:P169 ?ceo . }
        OPTIONAL { ?item wdt:P452 ?industry . }
        SERVICE wikibase:label { bd:serviceParam wikibase:language "en" . }
      } LIMIT 10`);
    for (const r of results) {
      if (r.countryLabel?.value) {
        const cid = `country:${r.countryLabel.value}`;
        nodes.push({ id: cid, label: r.countryLabel.value, type: 'country', properties: { source: 'Wikidata' } });
        links.push({ source: rootId, target: cid, label: 'HEADQUARTERED' });
      }
      if (r.parentLabel?.value) {
        const pid = `company:${r.parentLabel.value}`;
        nodes.push({ id: pid, label: r.parentLabel.value, type: 'company', properties: { source: 'Wikidata' } });
        links.push({ source: rootId, target: pid, label: 'PARENT ORG' });
      }
      if (r.ceoLabel?.value) {
        const pid = `person:${r.ceoLabel.value}`;
        nodes.push({ id: pid, label: r.ceoLabel.value, type: 'person', properties: { role: 'CEO', source: 'Wikidata' } });
        links.push({ source: rootId, target: pid, label: 'CEO' });
      }
    }
  } catch (e) { console.warn('[INTEL] Wikidata company error:', e.message); }

  addSanctionsToGraph(id, rootId, nodes, links);
  const result = dedup(nodes, links);
  wdCacheSet(`company:${id}`, result);
  return result;
}

async function resolvePerson(id) {
  const rootId = `person:${id}`;
  const nodes = [], links = [];
  const cached = wdCacheGet(`person:${id}`);
  if (cached) return { ...cached };

  try {
    const qid = await wdSearch(id);
    const filter = qid
      ? `VALUES ?item { wd:${qid} }`
      : `?item rdfs:label "${id}"@en . ?item wdt:P31 wd:Q5 .`;
    const results = await sparql(`
      SELECT ?item ?itemLabel ?nationalityLabel ?employerLabel ?positionLabel WHERE {
        ${filter}
        OPTIONAL { ?item wdt:P27 ?nationality . }
        OPTIONAL { ?item wdt:P108 ?employer . }
        OPTIONAL { ?item wdt:P39 ?position . }
        SERVICE wikibase:label { bd:serviceParam wikibase:language "en" . }
      } LIMIT 10`);
    for (const r of results) {
      if (r.nationalityLabel?.value) {
        const cid = `country:${r.nationalityLabel.value}`;
        nodes.push({ id: cid, label: r.nationalityLabel.value, type: 'country', properties: { source: 'Wikidata' } });
        links.push({ source: rootId, target: cid, label: 'NATIONALITY' });
      }
      if (r.employerLabel?.value) {
        const eid = `company:${r.employerLabel.value}`;
        nodes.push({ id: eid, label: r.employerLabel.value, type: 'company', properties: { source: 'Wikidata' } });
        links.push({ source: rootId, target: eid, label: 'EMPLOYER' });
      }
      if (r.positionLabel?.value) {
        const pid = `event:${r.positionLabel.value}`;
        nodes.push({ id: pid, label: r.positionLabel.value, type: 'event', properties: { source: 'Wikidata' } });
        links.push({ source: rootId, target: pid, label: 'POSITION HELD' });
      }
    }
  } catch (e) { console.warn('[INTEL] Wikidata person error:', e.message); }

  addSanctionsToGraph(id, rootId, nodes, links);
  const result = dedup(nodes, links);
  wdCacheSet(`person:${id}`, result);
  return result;
}

async function resolveIP(id) {
  const rootId = `ip:${id}`;
  const nodes = [], links = [];
  const cached = wdCacheGet(`ip:${id}`);
  if (cached) return { ...cached };

  // Step 1: ip-api.com — geolocation, ISP, ASN, proxy/hosting detection
  try {
    const ipApiUrl = `http://ip-api.com/json/${encodeURIComponent(id)}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting`;
    const parsed = new URL(ipApiUrl);
    if (!ALLOWED_DOMAINS.has(parsed.hostname)) throw new Error(`Blocked domain: ${parsed.hostname}`);
    const res = await fetch(ipApiUrl, { signal: AbortSignal.timeout(8000) });
    if (res.ok) {
      const data = await res.json();
      if (data.status === 'success') {
        // ISP node
        if (data.isp) {
          const ispId = `company:${data.isp}`;
          nodes.push({ id: ispId, label: data.isp, type: 'company', properties: { role: 'ISP', org: data.org || '', source: 'ip-api.com' } });
          links.push({ source: rootId, target: ispId, label: 'HOSTED_BY' });
          addSanctionsToGraph(data.isp, rootId, nodes, links);
        }

        // ASN node
        if (data.as) {
          const asLabel = data.asname || data.as;
          const asId = `company:${data.as}`;
          nodes.push({ id: asId, label: asLabel, type: 'company', properties: { as_number: data.as, source: 'ip-api.com' } });
          links.push({ source: rootId, target: asId, label: 'ASN' });
        }

        // Country node
        if (data.country) {
          const cid = `country:${data.country}`;
          nodes.push({ id: cid, label: data.country, type: 'country', properties: { code: data.countryCode || '', source: 'ip-api.com' } });
          links.push({ source: rootId, target: cid, label: 'LOCATED_IN' });
          addSanctionsToGraph(data.country, rootId, nodes, links);
        }

        // City node (as event type with lat/lng)
        if (data.city) {
          const cityId = `event:${data.city}`;
          nodes.push({
            id: cityId, label: data.city, type: 'event',
            properties: {
              lat: data.lat, lon: data.lon, region: data.regionName || '',
              zip: data.zip || '', timezone: data.timezone || '', source: 'ip-api.com',
            },
          });
          links.push({ source: rootId, target: cityId, label: 'GEOLOCATED' });
        }

        // Tag proxy/hosting/mobile flags on the root IP node
        nodes.push({
          id: rootId, label: id, type: 'ip',
          properties: {
            proxy: !!data.proxy, hosting: !!data.hosting, mobile: !!data.mobile,
            source: 'ip-api.com',
          },
        });
      }
    }
  } catch (e) { console.warn('[INTEL] ip-api.com error:', e.message); }

  // Step 2: RIPEstat WHOIS
  try {
    const whoisUrl = `https://stat.ripe.net/data/whois/data.json?resource=${encodeURIComponent(id)}`;
    const parsed = new URL(whoisUrl);
    if (!ALLOWED_DOMAINS.has(parsed.hostname)) throw new Error(`Blocked domain: ${parsed.hostname}`);
    const res = await fetch(whoisUrl, { signal: AbortSignal.timeout(8000) });
    if (res.ok) {
      const json = await res.json();
      const records = json.data?.records || [];
      for (const record of records) {
        for (const field of record) {
          if (field.key === 'netname' || field.key === 'NetName') {
            const netId = `company:${field.value}`;
            nodes.push({ id: netId, label: field.value, type: 'company', properties: { role: 'Network', source: 'RIPEstat WHOIS' } });
            links.push({ source: rootId, target: netId, label: 'HOSTED_BY' });
          }
        }
      }
    }
  } catch (e) { console.warn('[INTEL] RIPEstat WHOIS error:', e.message); }

  // Step 3: RIPEstat Abuse Contact
  try {
    const abuseUrl = `https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${encodeURIComponent(id)}`;
    const parsed = new URL(abuseUrl);
    if (!ALLOWED_DOMAINS.has(parsed.hostname)) throw new Error(`Blocked domain: ${parsed.hostname}`);
    const res = await fetch(abuseUrl, { signal: AbortSignal.timeout(8000) });
    if (res.ok) {
      const json = await res.json();
      const contacts = json.data?.abuse_contacts || [];
      for (const email of contacts) {
        if (email) {
          const eid = `person:${email}`;
          nodes.push({ id: eid, label: email, type: 'person', properties: { role: 'Abuse Contact', source: 'RIPEstat' } });
          links.push({ source: rootId, target: eid, label: 'ABUSE CONTACT' });
        }
      }
    }
  } catch (e) { console.warn('[INTEL] RIPEstat abuse-contact error:', e.message); }

  // Step 4: RIPEstat Network Info
  try {
    const netUrl = `https://stat.ripe.net/data/network-info/data.json?resource=${encodeURIComponent(id)}`;
    const parsed = new URL(netUrl);
    if (!ALLOWED_DOMAINS.has(parsed.hostname)) throw new Error(`Blocked domain: ${parsed.hostname}`);
    const res = await fetch(netUrl, { signal: AbortSignal.timeout(8000) });
    if (res.ok) {
      const json = await res.json();
      const prefix = json.data?.prefix;
      const asns = json.data?.asns || [];
      if (prefix) {
        const prefId = `ip:${prefix}`;
        nodes.push({ id: prefId, label: prefix, type: 'ip', properties: { role: 'Prefix', source: 'RIPEstat' } });
        links.push({ source: rootId, target: prefId, label: 'PREFIX' });
      }
      for (const asn of asns) {
        const asnId = `company:AS${asn}`;
        nodes.push({ id: asnId, label: `AS${asn}`, type: 'company', properties: { as_number: `AS${asn}`, source: 'RIPEstat' } });
        links.push({ source: rootId, target: asnId, label: 'ASN' });
      }
    }
  } catch (e) { console.warn('[INTEL] RIPEstat network-info error:', e.message); }

  const result = dedup(nodes, links);
  wdCacheSet(`ip:${id}`, result);
  return result;
}

async function resolveCountry(id) {
  const rootId = `country:${id}`;
  const nodes = [], links = [];
  const cached = wdCacheGet(`country:${id}`);
  if (cached) return { ...cached };

  try {
    const qid = await wdSearch(id);
    const filter = qid
      ? `VALUES ?item { wd:${qid} }`
      : `?item rdfs:label "${id}"@en . ?item wdt:P31 wd:Q6256 .`;
    const results = await sparql(`
      SELECT ?item ?itemLabel ?headLabel ?capitalLabel ?population ?gdp
             ?tld ?callingCode ?memberOfLabel ?neighborLabel WHERE {
        ${filter}
        OPTIONAL { ?item wdt:P35 ?head . }
        OPTIONAL { ?item wdt:P36 ?capital . }
        OPTIONAL { ?item wdt:P1082 ?population . }
        OPTIONAL { ?item wdt:P2131 ?gdp . }
        OPTIONAL { ?item wdt:P78 ?tld . }
        OPTIONAL { ?item wdt:P474 ?callingCode . }
        OPTIONAL { ?item wdt:P463 ?memberOf . }
        OPTIONAL { ?item wdt:P47 ?neighbor . }
        SERVICE wikibase:label { bd:serviceParam wikibase:language "en" . }
      } LIMIT 50`);

    const seenHeads = new Set();
    const seenMembers = new Set();
    const seenNeighbors = new Set();
    let propsSet = false;

    for (const r of results) {
      // Head of state/government
      if (r.headLabel?.value && !seenHeads.has(r.headLabel.value)) {
        seenHeads.add(r.headLabel.value);
        const hid = `person:${r.headLabel.value}`;
        nodes.push({ id: hid, label: r.headLabel.value, type: 'person', properties: { role: 'Head of State', source: 'Wikidata' } });
        links.push({ source: rootId, target: hid, label: 'HEAD OF STATE' });
      }

      // Capital city
      if (r.capitalLabel?.value && !propsSet) {
        const capId = `event:${r.capitalLabel.value}`;
        nodes.push({ id: capId, label: r.capitalLabel.value, type: 'event', properties: { role: 'Capital', source: 'Wikidata' } });
        links.push({ source: rootId, target: capId, label: 'CAPITAL' });
      }

      // Country properties (population, GDP, TLD, calling code)
      if (!propsSet) {
        const props = { source: 'Wikidata' };
        if (r.population?.value) props.population = r.population.value;
        if (r.gdp?.value) props.gdp = r.gdp.value;
        if (r.tld?.value) props.tld = r.tld.value;
        if (r.callingCode?.value) props.calling_code = r.callingCode.value;
        nodes.push({ id: rootId, label: id, type: 'country', properties: props });
        propsSet = true;
      }

      // Member of (UN, NATO, EU, etc.)
      if (r.memberOfLabel?.value && !seenMembers.has(r.memberOfLabel.value)) {
        seenMembers.add(r.memberOfLabel.value);
        const mid = `company:${r.memberOfLabel.value}`;
        nodes.push({ id: mid, label: r.memberOfLabel.value, type: 'company', properties: { role: 'Organization', source: 'Wikidata' } });
        links.push({ source: rootId, target: mid, label: 'MEMBER OF' });
      }

      // Neighboring countries
      if (r.neighborLabel?.value && !seenNeighbors.has(r.neighborLabel.value)) {
        seenNeighbors.add(r.neighborLabel.value);
        const nid = `country:${r.neighborLabel.value}`;
        nodes.push({ id: nid, label: r.neighborLabel.value, type: 'country', properties: { source: 'Wikidata' } });
        links.push({ source: rootId, target: nid, label: 'NEIGHBOR' });
      }
    }
  } catch (e) { console.warn('[INTEL] Wikidata country error:', e.message); }

  addSanctionsToGraph(id, rootId, nodes, links);
  const result = dedup(nodes, links);
  wdCacheSet(`country:${id}`, result);
  return result;
}

const RESOLVERS = { aircraft: resolveAircraft, vessel: resolveVessel, company: resolveCompany, person: resolvePerson, ip: resolveIP, country: resolveCountry };
const ALLOWED_TYPES = new Set(Object.keys(RESOLVERS));

// ════════════════════════════════════════════════════
// §6 — RATE LIMITER
// ════════════════════════════════════════════════════

const rateMap = new Map();

function isRateLimited(ip, limit = 30, windowMs = 60000) {
  const now = Date.now();
  for (const [k, v] of rateMap) { if (now > v.resetAt) rateMap.delete(k); }
  const entry = rateMap.get(ip);
  if (!entry || now > entry.resetAt) { rateMap.set(ip, { count: 1, resetAt: now + windowMs }); return false; }
  entry.count++;
  return entry.count > limit;
}

// ════════════════════════════════════════════════════
// §7 — EXPRESS ROUTES
// ════════════════════════════════════════════════════

app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    sanctions_entries: sanctionsIndex.entries.length,
    sanctions_loaded_at: sanctionsIndex.fetchedAt ? new Date(sanctionsIndex.fetchedAt).toISOString() : null,
    wikidata_cache_size: wdCache.size,
    uptime_seconds: Math.floor(process.uptime()),
  });
});

app.get('/resolve', async (req, res) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
  if (isRateLimited(ip)) return res.status(429).json({ error: 'Rate limit exceeded' });

  const type = (req.query.type || '').toLowerCase().trim();
  const rawId = (req.query.id || '').trim();

  if (!type || !ALLOWED_TYPES.has(type)) {
    return res.status(400).json({ error: `Invalid type. Allowed: ${[...ALLOWED_TYPES].join(', ')}` });
  }
  if (!rawId || rawId.length < 2 || rawId.length > 200) {
    return res.status(400).json({ error: 'Invalid id (2-200 chars)' });
  }

  const id = sanitizeId(rawId);
  if (id.length < 2) return res.status(400).json({ error: 'ID contains too many invalid characters' });

  try {
    const resolver = RESOLVERS[type];
    // Pass extra properties for aircraft resolution (registration, model, etc.)
    const props = {};
    if (req.query.registration) props.registration = sanitizeId(req.query.registration);
    if (req.query.model) props.model = sanitizeId(req.query.model);
    if (req.query.icao24) props.icao24 = sanitizeId(req.query.icao24);
    const result = await resolver(id, props);
    res.set('Cache-Control', 'public, s-maxage=3600, stale-while-revalidate=7200');
    res.json({
      nodes: result.nodes,
      links: result.links,
      entity: { type, id },
      source: 'OSIRIS Intelligence Layer',
      sanctions_index_size: sanctionsIndex.entries.length,
      wikidata_cache_hits: wdCache.size,
      timestamp: new Date().toISOString(),
    });
  } catch (e) {
    console.error('[INTEL] Resolve error:', e);
    res.status(500).json({ error: 'Resolution failed', nodes: [], links: [] });
  }
});

// ════════════════════════════════════════════════════
// §8 — STARTUP
// ════════════════════════════════════════════════════

async function boot() {
  console.log('[INTEL] OSIRIS Intelligence Layer starting...');
  await loadSanctions();
  // Refresh sanctions every 24h
  setInterval(() => loadSanctions(), SDN_REFRESH_MS);

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[INTEL] Intelligence Layer ready on port ${PORT}`);
    console.log(`[INTEL] Sanctions: ${sanctionsIndex.entries.length} entities indexed`);
    console.log(`[INTEL] Resolve endpoint: GET /resolve?type=<type>&id=<id>`);
  });
}

boot().catch(e => { console.error('[INTEL] Fatal:', e); process.exit(1); });
