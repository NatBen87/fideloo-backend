'use strict';
const { PKPass } = require('passkit-generator');
const fs = require('fs');
const path = require('path');
const os = require('os');

function hexToRgb(hex) {
  if (!hex || !hex.startsWith('#') || hex.length < 7) return 'rgb(245, 158, 11)';
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  if (isNaN(r) || isNaN(g) || isNaN(b)) return 'rgb(245, 158, 11)';
  return `rgb(${r}, ${g}, ${b})`;
}

async function generateAppleWalletPass(customer, merchant) {
  const certPem = process.env.APPLE_CERT_PEM;
  const keyPem = process.env.APPLE_KEY_PEM;
  const wwdrPem = process.env.APPLE_WWDR_PEM;

  if (!certPem || !keyPem || !wwdrPem) {
    throw new Error('Missing Apple Wallet env vars');
  }

  const PLACEHOLDER_ICON = Buffer.from(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAABmJLR0QA/wD/AP+gvaeTAAAADUlEQVQI12P4//8/AwAI/AL+hc2rNAAAAABJRU5ErkJggg==',
    'base64'
  );

  const passJson = {
    passTypeIdentifier: 'pass.com.fideloo.fidelite',
    teamIdentifier: 'HK48W747TG',
    organizationName: merchant.business_name || 'Fideloo',
    description: `Carte fidelite ${merchant.business_name || 'Fideloo'}`,
    serialNumber: customer.id,
    formatVersion: 1,
    backgroundColor: hexToRgb(merchant.primary_color),
    foregroundColor: 'rgb(255, 255, 255)',
    labelColor: 'rgb(255, 255, 255)',
    storeCard: {
      headerFields: [
        { key: 'points', label: 'Points', value: String(customer.points ?? 0) }
      ],
      primaryFields: [
        { key: 'name', label: 'Client', value: customer.name || 'Client' }
      ],
      secondaryFields: [
        { key: 'reward', label: 'Recompense', value: merchant.reward_description || '1 recompense offerte' }
      ],
      backFields: [
        { key: 'commerce', label: 'Commerce', value: merchant.business_name || '' },
        { key: 'objectif', label: 'Points pour recompense', value: String(merchant.reward_threshold ?? 10) }
      ]
    }
  };

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pass-'));
  const modelDir = path.join(tmpDir, 'fideloo.pass');
  fs.mkdirSync(modelDir);

  fs.writeFileSync(path.join(modelDir, 'pass.json'), JSON.stringify(passJson));
  fs.writeFileSync(path.join(modelDir, 'icon.png'), PLACEHOLDER_ICON);
  fs.writeFileSync(path.join(modelDir, 'icon@2x.png'), PLACEHOLDER_ICON);

  const pass = await PKPass.from({
    model: modelDir,
    certificates: {
      wwdr: Buffer.from(wwdrPem),
      signerCert: Buffer.from(certPem),
      signerKey: Buffer.from(keyPem),
    }
  }, { serialNumber: customer.id });

  const buffer = pass.getAsBuffer();
  fs.rmSync(tmpDir, { recursive: true, force: true });
  return buffer;
}

module.exports = { generateAppleWalletPass };