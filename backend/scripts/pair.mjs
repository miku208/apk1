#!/usr/bin/env node
// Create a pairing code for the Android app. Run on the VPS.
import { ensureDirs } from '../src/config.mjs';
import { openDatabase } from '../src/db.mjs';
import { createPairingSession, ensureOwner } from '../src/auth.mjs';
import { config } from '../src/config.mjs';

ensureDirs();
openDatabase();
ensureOwner();
const session = createPairingSession({ createdBy: 'cli' });
console.log('');
console.log('  Kode pairing : ' + session.code);
console.log('  Berlaku      : ' + Math.round(config.pairingTtlMs / 60000) + ' menit');
console.log('  Backend      : ' + config.publicBaseUrl + (config.basePath || ''));
console.log('');
console.log('  Buka aplikasi MikuHost Lifeform → Settings → Pair device, lalu masukkan kode di atas.');
console.log('');
