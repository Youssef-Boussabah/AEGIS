#!/usr/bin/env node
// Offline public-summary import walkthrough against an already-running local product.
const fs = require('node:fs/promises');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { chromium, expect } = require(require.resolve('@playwright/test', {
  paths: [path.resolve(__dirname, '../platform/dashboard')],
}));

async function main() {
  const [origin, summaryPath, expectedDigest, outputDirectory] = process.argv.slice(2);
  const url = new URL(origin);
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || url.username || url.password ||
      url.search || url.hash || !/^[a-f0-9]{64}$/.test(expectedDigest || '') || !outputDirectory) {
    throw new Error('Usage: node scripts/check-research-dashboard.cjs http://127.0.0.1:PORT SUMMARY SHA256 PRIVATE_OUTPUT_DIR');
  }
  const bytes = await fs.readFile(summaryPath);
  if (createHash('sha256').update(bytes).digest('hex') !== expectedDigest) throw new Error('Public summary digest mismatch');
  const summary = JSON.parse(bytes).summary;
  if (summary.generation_status !== 'invalid_output' || summary.candidate_sha256 !== null ||
      summary.post_hoc_review?.post_hoc_status !== 'candidate_text_revalidated_but_behaviorally_unscored') {
    throw new Error('Expected the preserved historical result and separate post-hoc unscored review');
  }
  await fs.mkdir(outputDirectory, { mode: 0o700 }); // refuses existing output
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    let posts = 0;
    page.on('request', request => { if (request.method() === 'POST') posts++; });
    await page.goto(origin);
    await page.getByRole('button', { name: 'Research evidence', exact: true }).click();
    await page.getByLabel('Evidence JSON').setInputFiles({ name: 'public-summary.json', mimeType: 'application/json', buffer: bytes });
    await page.getByLabel('Expected summary SHA-256').fill(expectedDigest);
    await page.getByRole('button', { name: 'Verify and load summary', exact: true }).click();
    const review = page.getByRole('region', { name: 'Post-hoc parser review', exact: true });
    await expect(review.getByText('Candidate text revalidated · unscored', { exact: true })).toBeVisible();
    await expect(review.getByText(summary.post_hoc_review.post_hoc_status, { exact: true })).toBeVisible();
    await expect(page.getByText('No candidate recorded', { exact: true })).toBeVisible();
    await expect(page.getByText(summary.requested_model, { exact: true }).first()).toBeVisible();
    await expect(review.getByText('aegis.lab.completion-parser.v1', { exact: true })).toBeVisible();
    await expect(review.getByText('aegis.lab.nebius-reasoning-text.v2', { exact: true })).toBeVisible();
    await page.screenshot({ path: path.join(outputDirectory, 'research-desktop.png'), fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    await expect(review).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await page.screenshot({ path: path.join(outputDirectory, 'research-mobile.png'), fullPage: true });
    await page.getByRole('button', { name: 'Results', exact: true }).click();
    await expect(page.getByRole('region', { name: 'Post-hoc parser review', exact: true })).toBeVisible();
    expect(posts).toBe(0);
    console.log(JSON.stringify({ summary_sha256: expectedDigest, desktop: 'passed', mobile: 'passed',
      results: 'passed', original_generation_status: summary.generation_status,
      post_hoc_status: summary.post_hoc_review.post_hoc_status, browser_posts: posts }));
  } finally {
    await browser.close();
  }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
