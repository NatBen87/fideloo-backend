'use strict';
const { PKPass } = require('passkit-generator');

// Minimal 1×1 PNG placeholder — Apple Wallet requires icon.png in the bundle.
// Replace with a real 29×29 (icon.png) and 58×58 (icon@2x.png) image for production.
const PLACEHOLDER_ICON = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAABmJLR0QA/wD/AP+gvaeTAAAADUlEQVQI12P4//8/AwAI/AL+hc2rNAAAAABJRU5ErkJggg==',
  'base64'
);

function hexToRgb(hex) {
  if (!hex || !hex.startsWith('#') || hex.length < 7) return 'rgb(245, 158, 11)';
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  if (isNaN(r) || isNaN(g) || isNaN(b)) return 'rgb(245, 158, 11)';
  return `rgb(${r}, ${g}, ${b})`;
}

async function generateAppleWalletPass(customer, merchant) {
  // Certificates are stored as Railway environment variables (multi-line PEM strings).
  // Set APPLE_CERT_PEM, APPLE_KEY_PEM, APPLE_WWDR_PEM in the Railway dashboard.
  const certPem  = process.env.APPLE_CERT_PEM;
  const keyPem   = process.env.APPLE_KEY_PEM;
  const wwdrPem  = process.env.APPLE_WWDR_PEM;

  if (!certPem || !keyPem || !wwdrPem) {
    throw new Error(
      'Missing Apple Wallet env vars: APPLE_CERT_PEM, APPLE_KEY_PEM, APPLE_WWDR_PEM'
    );
  }

  const passJson = {
    passTypeIdentifier: 'pass.com.fideloo.fidelite',
    teamIdentifier: 'HK48W747TG',
    organizationName: merchant.business_name || 'Fideloo',
    description: `Carte fidélité ${merchant.business_name || 'Fideloo'}`,
    serialNumber: customer.id,
    formatVersion: 1,
    backgroundColor: hexToRgb(merchant.primary_color),
    foregroundColor: 'rgb(255, 255, 255)',
    labelColor: 'rgb(255, 255, 255)',
    storeCard: {
      headerFields: [
        { key: 'points', label: 'Points', value: String(customer.points ?? 0) },
      ],
      primaryFields: [
        { key: 'name', label: 'Client', value: customer.name },
      ],
      secondaryFields: [
        {
          key: 'reward',
          label: 'Récompense',
          value: merchant.reward_description || '1 récompense offerte',
        },
      ],
      backFields: [
        { key: 'commerce', label: 'Commerce', value: merchant.business_name || '' },
        {
          key: 'objectif',
          label: 'Points pour récompense',
          value: String(merchant.reward_threshold ?? 10),
        },
      ],
    },
  };

  const pass = await PKPass.from(
    {
      model: {
        'pass.json': Buffer.from(JSON.stringify(passJson)),
        'icon.png': PLACEHOLDER_ICON,
        'icon@2x.png': PLACEHOLDER_ICON,
      },
      certificates: {
        wwdr:       Buffer.from(wwdrPem),
        signerCert: Buffer.from(certPem),
        signerKey:  Buffer.from(keyPem),
      },
    },
    { serialNumber: customer.id }
  );

  return pass.getAsBuffer();
}

module.exports = { generateAppleWalletPass };
