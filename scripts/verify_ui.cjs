#!/usr/bin/env node
/**
 * Reproducible static-browser smoke tests and visual snapshots.
 * Uses locally hosted site files (no external traffic needed).
 */
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require(process.env.PLAYWRIGHT_CORE_PATH || '/tmp/portfolio-qa/node_modules/playwright-core');

const BASE = process.env.QA_BASE || 'http://127.0.0.1:8765';
const CHROME = process.env.CHROME_PATH || '/usr/bin/google-chrome';
const OUTPUT = process.env.QA_OUTPUT || 'audit-artifacts';
const editorial = ['/', '/about/', '/research/', '/publications/', '/projects/', '/tools/', '/contact/', '/media/'];
const applications = ['/opengovsec/', '/tools/domain-risk-scan/', '/tools/osint-threat-radar/'];
const screenshots = [];
const failures = [];
fs.mkdirSync(OUTPUT, {recursive:true});
const browserOptions = {headless:true, executablePath:CHROME, args:['--no-sandbox','--disable-dev-shm-usage']};

(async () => {
  const browser = await chromium.launch(browserOptions);
  try {
    for (const viewport of [{name:'mobile',width:390,height:844},{name:'desktop',width:1440,height:900}]) {
      for (const route of [...editorial,...applications]) {
        const page = await browser.newPage({viewport:{width:viewport.width,height:viewport.height},deviceScaleFactor:1});
        const errors = [];
        page.on('pageerror', e => errors.push('JS: '+e.message));
        const response = await page.goto(BASE + route, {waitUntil:'networkidle',timeout:30000});
        await page.evaluate(()=>document.fonts.ready);
        const info = await page.evaluate(() => ({
          horizontalOverflow:document.documentElement.scrollWidth - window.innerWidth,
          fontReady:document.fonts.check('400 16px "DM Sans"'),
          h1:document.querySelectorAll('h1').length,
          nav:!!document.querySelector('.site-header .site-menu'),
          allImagesHaveAlt:[...document.images].every(i=>i.hasAttribute('alt')),
        }));
        if (!response || !response.ok()) errors.push('Response not OK: '+(response?.status() || 'none'));
        if (info.h1 !== 1) errors.push('Expected one H1, got '+info.h1);
        if (!info.allImagesHaveAlt) errors.push('Image without alt');
        if (editorial.includes(route) && info.horizontalOverflow > 8)
          errors.push('Horizontal overflow: '+info.horizontalOverflow+'px');
        if (route !== '/' && route !== '/contact/' && !info.nav)
          errors.push('Missing shared navigation');
        if (!info.fontReady) errors.push('Local DM Sans font unavailable');
        if (viewport.name === 'mobile' && page.locator('.site-header .site-menu summary').count() > 0) {
          await page.locator('.site-header .site-menu summary').click();
          const visible = await page.locator('.site-header .site-menu nav').isVisible();
          if (!visible) errors.push('Mobile navigation does not open');
        }
        if (route === '/publications/') {
          const all = await page.locator('article[data-article-topic]').count();
          await page.locator('button[data-topic-filter="ai"]').click();
          const visible = await page.locator('article[data-article-topic]:visible').count();
          if (all < 10 || visible < 1 || visible >= all)
            errors.push('Publication category filters broken');
        }
        if (route === '/') {
          await page.locator('button[data-filter="ai"]').click();
          const visible = await page.locator('a.article:visible').count();
          if (visible < 1 || visible >= 5) errors.push('Homepage feature filters broken');
        }
        const file = path.join(OUTPUT, `${route === '/' ? 'home' : route.replace(/\W+/g,'-').replace(/^-|-$/g,'')}-${viewport.name}.png`);
        if ((route === '/' || route === '/publications/' || route === '/research/') && !errors.length) {
          await page.screenshot({path:file, fullPage:true});
          screenshots.push(file);
        }
        console.log(JSON.stringify({route,viewport:viewport.name,...info,errors}));
        for (const error of errors) failures.push(`${viewport.name} ${route}: ${error}`);
        await page.close();
      }
    }
  } finally {
    await browser.close();
  }
  fs.writeFileSync(path.join(OUTPUT,'ui-summary.json'),JSON.stringify({failures,screenshots},null,2));
  if(failures.length){console.error('\nUI smoke test failures:', failures.join('\n'));process.exitCode=1}
  else console.log('UI smoke tests passed on mobile and desktop.');
})().catch(e=>{console.error(e);process.exitCode=1});
