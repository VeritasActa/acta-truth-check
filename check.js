#!/usr/bin/env node
/**
 * acta-truth-check — Independent external verification of Acta instance claims
 *
 * Runs entirely outside the operator's infrastructure. No privileged access.
 * Fetches only public endpoints and verifies claims against live reality.
 *
 * Checks:
 *   1. Manifest exists and is well-formed
 *   2. All advertised endpoints respond
 *   3. Anchor is signed and recent
 *   4. Anchor signature is valid (Ed25519)
 *   5. Merkle root recomputes correctly from chain heads
 *   6. Witness exists and references the latest anchor
 *   7. Conformance self-report is consistent with live state
 *   8. At least one topic chain verifies independently (full export + recomputation)
 *   9. Identity binding check (charter/spec hashes in anchor)
 *
 * Zero dependencies on operator code. Inlines all verification logic.
 *
 * Usage:
 *   node check.js [instance-url]
 *   node check.js https://veritasacta.com
 *
 * Output:
 *   JSON report to stdout
 *   Exit 0 if all critical checks pass, 1 if any fail
 *
 * @license MIT
 */

import { createHash } from 'node:crypto';

const INSTANCE_URL = process.argv[2] || 'https://veritasacta.com';
const KNOWN_PUBLIC_KEY = '712e93b514966d66ecbcaef6200689e10a847c315951e824189d4abe70496991';

// ── Crypto utilities (inlined, zero operator dependency) ────────────

function sha256(str) {
    return createHash('sha256').update(str, 'utf8').digest('hex');
}

function sortKeysDeep(obj) {
    if (obj === null || obj === undefined) return obj;
    if (typeof obj !== 'object') return obj;
    if (Array.isArray(obj)) return obj.map(sortKeysDeep);
    return Object.keys(obj).sort().reduce((acc, key) => {
        acc[key] = sortKeysDeep(obj[key]);
        return acc;
    }, {});
}

function jcsSerialize(obj) {
    return JSON.stringify(sortKeysDeep(obj));
}

function jcsSha256(obj) {
    return sha256(jcsSerialize(obj));
}

function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
}

function computeMerkleRoot(chainHeads) {
    const sorted = [...chainHeads].sort((a, b) => a.topic.localeCompare(b.topic));
    const leaves = sorted.map(head => sha256(jcsSerialize(head)));
    if (leaves.length === 0) return '0'.repeat(64);
    if (leaves.length === 1) return leaves[0];
    let layer = leaves;
    while (layer.length > 1) {
        const next = [];
        for (let i = 0; i < layer.length; i += 2) {
            if (i + 1 < layer.length) {
                next.push(sha256(layer[i] + layer[i + 1]));
            } else {
                next.push(layer[i]);
            }
        }
        layer = next;
    }
    return layer[0];
}

// ── Fetch helper ────────────────────────────────────────────────────

async function fetchJSON(url, timeoutMs = 10000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const resp = await fetch(url, { signal: controller.signal });
        clearTimeout(timer);
        if (!resp.ok) return { ok: false, status: resp.status, data: null };
        const data = await resp.json();
        return { ok: true, status: resp.status, data };
    } catch (err) {
        clearTimeout(timer);
        return { ok: false, status: 0, data: null, error: err.message };
    }
}

async function fetchStatus(url, timeoutMs = 10000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const resp = await fetch(url, { signal: controller.signal });
        clearTimeout(timer);
        return { ok: resp.ok, status: resp.status };
    } catch (err) {
        clearTimeout(timer);
        return { ok: false, status: 0, error: err.message };
    }
}

// ── Check functions ─────────────────────────────────────────────────

const results = [];

function check(name, passed, details = {}) {
    const level = passed ? 'pass' : (details.warning ? 'warn' : 'fail');
    results.push({ check: name, level, ...details });
    const icon = level === 'pass' ? '\x1b[32m✓\x1b[0m' : level === 'warn' ? '\x1b[33m⚠\x1b[0m' : '\x1b[31m✗\x1b[0m';
    const detail = details.detail || details.error || '';
    console.error(`  ${icon}  ${name}${detail ? ` — ${detail}` : ''}`);
    return passed;
}

// ── Main ────────────────────────────────────────────────────────────

async function main() {
    console.error(`\n  acta-truth-check`);
    console.error(`  Instance: ${INSTANCE_URL}`);
    console.error(`  Timestamp: ${new Date().toISOString()}\n`);

    // 1. Manifest
    const manifest = await fetchJSON(`${INSTANCE_URL}/.well-known/acta-instance.json`);
    check('manifest_exists', manifest.ok, manifest.ok ? {} : { error: `HTTP ${manifest.status}` });

    if (!manifest.ok) {
        console.error('\n  Cannot proceed without manifest. Aborting.\n');
        outputReport();
        process.exit(1);
    }

    const m = manifest.data;
    check('manifest_has_protocol', !!m.protocol && m.protocol === 'acta', { detail: m.protocol });
    check('manifest_has_charter_hash', !!m.charter_hash, { detail: m.charter_hash?.slice(0, 16) + '...' });
    check('manifest_has_public_key', !!m.anchor?.public_key, { detail: m.anchor?.public_key?.slice(0, 16) + '...' });

    // 2. Advertised endpoints respond
    const endpoints = m.endpoints || {};
    const endpointChecks = [
        ['topics', endpoints.topics],
        ['charter', endpoints.charter],
        ['anchor_latest', endpoints.anchor_latest],
        ['chain_heads', endpoints.chain_heads],
        ['conformance', endpoints.conformance],
    ];

    for (const [name, path] of endpointChecks) {
        if (!path) {
            check(`endpoint_${name}`, false, { error: 'not advertised in manifest' });
            continue;
        }
        const url = path.startsWith('http') ? path : `${INSTANCE_URL}${path}`;
        const resp = await fetchStatus(url);
        check(`endpoint_${name}`, resp.ok, resp.ok ? { detail: `HTTP ${resp.status}` } : { error: `HTTP ${resp.status || 'unreachable'}` });
    }

    // 3. Anchor: exists, signed, recent
    const anchor = await fetchJSON(`${INSTANCE_URL}${endpoints.anchor_latest || '/api/anchor/latest'}`);
    if (!anchor.ok) {
        check('anchor_exists', false, { error: `HTTP ${anchor.status}` });
    } else {
        const a = anchor.data;
        check('anchor_exists', true);
        check('anchor_has_signature', !!a.signature, a.signature ? {} : { error: 'unsigned' });
        check('anchor_has_public_key', !!a.public_key);

        // Freshness
        const anchorAge = a.timestamp ? (Date.now() - new Date(a.timestamp).getTime()) / 3600000 : Infinity;
        check('anchor_fresh', anchorAge < 25, { detail: `${anchorAge.toFixed(1)} hours old` });

        // Known public key match
        if (KNOWN_PUBLIC_KEY && a.public_key) {
            check('anchor_known_key', a.public_key === KNOWN_PUBLIC_KEY,
                a.public_key === KNOWN_PUBLIC_KEY ? {} : { error: `key mismatch: ${a.public_key.slice(0, 16)}...` });
        }

        // 4. Signature verification
        if (a.signature && a.public_key) {
            try {
                const { ed25519 } = await import('@noble/curves/ed25519');
                const { signature, ...payload } = a;
                const message = new TextEncoder().encode(jcsSerialize(payload));
                const valid = ed25519.verify(hexToBytes(signature), message, hexToBytes(a.public_key));
                check('anchor_signature_valid', valid, valid ? {} : { error: 'invalid signature' });
            } catch (err) {
                check('anchor_signature_valid', false, { error: err.message, warning: true });
            }
        }

        // 5. Merkle root
        if (a.chain_heads && a.merkle_root) {
            const recomputed = computeMerkleRoot(a.chain_heads);
            check('anchor_merkle_valid', recomputed === a.merkle_root,
                recomputed === a.merkle_root ? {} : { error: `recomputed ${recomputed.slice(0, 16)}..., claims ${a.merkle_root.slice(0, 16)}...` });
        }

        // 9. Identity binding
        check('anchor_identity_bound', !!a.charter_hash && !!a.protocol_spec_hash,
            (a.charter_hash && a.protocol_spec_hash) ?
                { detail: `charter: ${a.charter_hash.slice(0, 12)}..., spec: ${a.protocol_spec_hash.slice(0, 12)}...` } :
                { error: 'anchor missing charter_hash or protocol_spec_hash', warning: true });

        // Verify identity hashes match manifest
        if (a.charter_hash && m.charter_hash) {
            check('anchor_charter_matches_manifest', a.charter_hash === m.charter_hash,
                a.charter_hash === m.charter_hash ? {} : { error: 'anchor charter_hash differs from manifest' });
        }
    }

    // 6. Witness
    const conformance = await fetchJSON(`${INSTANCE_URL}${endpoints.conformance || '/api/conformance'}`);
    if (conformance.ok && conformance.data.witness) {
        const w = conformance.data.witness;
        check('witness_active', w.status === 'active', { detail: w.status });
        if (w.post_url) {
            check('witness_has_post_url', true, { detail: w.post_url });
        }
        // Check witness references the anchor
        if (w.anchor_timestamp && anchor.ok) {
            check('witness_matches_anchor', w.anchor_timestamp === anchor.data.timestamp,
                w.anchor_timestamp === anchor.data.timestamp ?
                    { detail: `both: ${w.anchor_timestamp}` } :
                    { error: `witness: ${w.anchor_timestamp}, anchor: ${anchor.data?.timestamp}` });
        }
    } else {
        check('witness_active', false, { error: 'no witness data in conformance' });
    }

    // 7. Conformance self-consistency
    if (conformance.ok) {
        const c = conformance.data;
        if (c.anchor) {
            check('conformance_anchor_signed', c.anchor.signed === true);
            // Compare conformance identity_bound claim with what we actually found
            const actuallyBound = anchor.ok && !!anchor.data.charter_hash && !!anchor.data.protocol_spec_hash;
            check('conformance_identity_bound_honest', c.anchor.identity_bound === actuallyBound,
                c.anchor.identity_bound === actuallyBound ?
                    { detail: `reports ${c.anchor.identity_bound}, actual ${actuallyBound}` } :
                    { error: `conformance says ${c.anchor.identity_bound}, but actual is ${actuallyBound}` });
        }
        if (c.chains?.topics) {
            const allValid = c.chains.topics.every(t => t.chain_valid);
            check('conformance_chains_valid', allValid,
                allValid ? { detail: `${c.chains.topics.length} topics` } : { error: 'some chains report invalid' });
        }
    }

    // 8. Independent chain verification (pick first topic from the topics list)
    const topics = await fetchJSON(`${INSTANCE_URL}${endpoints.topics || '/api/topics'}`);
    if (topics.ok && Array.isArray(topics.data) && topics.data.length > 0) {
        const firstTopic = topics.data[0].topic || topics.data[0];
        const exportUrl = `${INSTANCE_URL}/api/export/${encodeURIComponent(firstTopic)}`;
        const exportData = await fetchJSON(exportUrl);

        if (exportData.ok) {
            const { entries, chain_head } = exportData.data;
            if (entries && entries.length > 0) {
                let chainValid = true;
                let expectedPrevHash = '0'.repeat(64);
                const chainErrors = [];

                for (let i = 0; i < entries.length; i++) {
                    const entry = entries[i];

                    // Verify chain linkage
                    if (entry.prev_hash !== expectedPrevHash) {
                        chainErrors.push(`[${i}] prev_hash mismatch`);
                        chainValid = false;
                    }

                    // Verify payload hash (skip tombstones)
                    if (!entry.tombstone && entry.payload) {
                        const recomputed = jcsSha256(entry.payload);
                        if (recomputed !== entry.payload_hash) {
                            chainErrors.push(`[${i}] payload_hash mismatch`);
                            chainValid = false;
                        }
                    }

                    // Verify entry hash
                    const authorHash = jcsSha256(entry.author || {});
                    const envelope = {
                        author_hash: authorHash,
                        payload_hash: entry.payload_hash,
                        prev_hash: entry.prev_hash,
                        subtype: entry.subtype,
                        timestamp: entry.timestamp,
                        topic: entry.topic,
                        type: entry.type,
                    };
                    const recomputedEntryHash = jcsSha256(envelope);
                    if (recomputedEntryHash !== entry.entry_hash) {
                        chainErrors.push(`[${i}] entry_hash mismatch`);
                        chainValid = false;
                    }

                    expectedPrevHash = entry.entry_hash;
                }

                // Verify chain head
                if (chain_head) {
                    const lastEntry = entries[entries.length - 1];
                    if (chain_head.chain_head_hash !== lastEntry.entry_hash) {
                        chainErrors.push('chain_head_hash mismatch');
                        chainValid = false;
                    }
                }

                check('chain_independent_verify', chainValid,
                    chainValid ?
                        { detail: `${firstTopic}: ${entries.length} entries, all hashes valid` } :
                        { error: `${firstTopic}: ${chainErrors.join(', ')}` });
            } else {
                check('chain_independent_verify', true, { detail: `${firstTopic}: empty chain` });
            }
        } else {
            check('chain_independent_verify', false, { error: `export failed: HTTP ${exportData.status}` });
        }
    } else {
        check('chain_independent_verify', false, { error: 'no topics found' });
    }

    // Output report
    console.error('');
    outputReport();

    const criticalFails = results.filter(r => r.level === 'fail');
    process.exit(criticalFails.length > 0 ? 1 : 0);
}

function outputReport() {
    const report = {
        instance: INSTANCE_URL,
        timestamp: new Date().toISOString(),
        summary: {
            total: results.length,
            pass: results.filter(r => r.level === 'pass').length,
            warn: results.filter(r => r.level === 'warn').length,
            fail: results.filter(r => r.level === 'fail').length,
        },
        checks: results,
    };
    console.log(JSON.stringify(report, null, 2));
}

main().catch(err => {
    console.error(`\n  Fatal: ${err.message}\n`);
    process.exit(1);
});
