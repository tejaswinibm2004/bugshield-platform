/**
 * Outbound email for member invitations.
 *
 * Honesty rule: `delivered: true` is only returned when SMTP actually accepted
 * the message. When SMTP is not configured the mail is written to a local
 * outbox and the caller is told it was NOT delivered, so the UI cannot imply
 * an email was sent when it was not.
 */
import fs from 'node:fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'node:module';

// This package is ESM ("type": "module"), so load the CommonJS mailer via
// createRequire rather than a bare require().
const require = createRequire(import.meta.url);

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUTBOX = path.join(__dirname, '../../data/outbox');

let transporter = null;
let transporterError = null;

function buildTransport() {
  if (transporter || transporterError) return transporter;
  const url = process.env.SMTP_URL;
  const host = process.env.SMTP_HOST;
  if (!url && !host) {
    transporterError = 'SMTP is not configured. Set SMTP_URL or SMTP_HOST plus SMTP_USER/SMTP_PASS.';
    return null;
  }
  try {
    // Loaded lazily so the platform still starts when mail is not configured.
    const nodemailer = require('nodemailer');
    transporter = url
      ? nodemailer.createTransport(url)
      : nodemailer.createTransport({
        host,
        port: Number(process.env.SMTP_PORT || 587),
        secure: String(process.env.SMTP_SECURE || 'false') === 'true',
        auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined
      });
  } catch (e) {
    transporterError = `Could not initialise mail transport: ${e.message}`;
    transporter = null;
  }
  return transporter;
}

export function isConfigured() {
  return !!(process.env.SMTP_URL || process.env.SMTP_HOST);
}

/** Performs a real SMTP handshake. Never claims success without one. */
export async function verify() {
  const t = buildTransport();
  if (!t) return { ok: false, configured: false, error: transporterError };
  try {
    await t.verify();
    return { ok: true, configured: true };
  } catch (e) {
    return { ok: false, configured: true, error: `SMTP verification failed: ${e.message}` };
  }
}

function writeToOutbox(subject, text) {
  if (!fs.existsSync(OUTBOX)) fs.mkdirSync(OUTBOX, { recursive: true });
  const file = path.join(OUTBOX, `${Date.now()}-${Math.random().toString(36).slice(2, 8)}.eml`);
  fs.writeFileSync(file, [
    `Subject: ${subject}`,
    `Date: ${new Date().toUTCString()}`,
    'X-BugShield-Delivery: NOT-SENT (no SMTP transport configured)',
    '',
    text
  ].join('\n'), 'utf-8');
  return file;
}

/**
 * Send a member invitation.
 * @returns { delivered, transport, reason?, outboxFile? }
 */
export async function sendInviteEmail({ to, orgName, role, invitedBy, activationLink, platformOrigin }) {
  const subject = `You have been invited to ${orgName} on BugShield`;
  const link = activationLink.startsWith('http') ? activationLink : `${platformOrigin}${activationLink}`;

  const text = [
    `Hello,`,
    ``,
    `${invitedBy} invited you to join the "${orgName}" organisation on BugShield`,
    `as: ${role}`,
    ``,
    `Activate your account and choose a password (minimum 12 characters):`,
    link,
    ``,
    `This link can be used once and expires in 7 days.`,
    `If you were not expecting this invitation, you can ignore this email.`,
    ``,
    `— BugShield Multi-Agent Platform`
  ].join('\n');

  const t = buildTransport();
  if (!t) {
    const file = writeToOutbox(subject, text);
    return { delivered: false, transport: 'outbox', reason: transporterError, outboxFile: file };
  }

  try {
    await t.sendMail({
      from: process.env.SMTP_FROM || `BugShield <no-reply@${process.env.SMTP_HOST || 'localhost'}>`,
      to,
      subject,
      text,
      html: `<p>Hello,</p>
<p><b>${invitedBy}</b> invited you to join <b>${orgName}</b> on BugShield as <b>${role}</b>.</p>
<p><a href="${link}">Activate your account and choose a password</a></p>
<p>This link can be used once and expires in 7 days.</p>
<p>If you were not expecting this, you can ignore this email.</p>`
    });
    return { delivered: true, transport: 'smtp' };
  } catch (e) {
    const file = writeToOutbox(subject, text);
    return { delivered: false, transport: 'outbox', reason: `SMTP send failed: ${e.message}`, outboxFile: file };
  }
}