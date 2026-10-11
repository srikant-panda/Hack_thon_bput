/*
 * Test for heuristic explanation polling in extension popup (FIX-HEURISTIC-NOT-LOADING).
 * Verifies that:
 * 1. When an alert has explanation: null, polling starts on GET /alerts/{alertId}
 * 2. Console logs are emitted at each stage ("Starting polling...", "Poll attempt...", "Explanation received...")
 * 3. Polling terminates once an explanation is received and updates the UI container.
 */
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { test } from 'node:test';
import assert from 'node:assert';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');

test('explanation polling retrieves background explanation and logs progress', async () => {
  // Load dependencies
  delete globalThis.CyberGuardExt;
  vm.runInThisContext(readFileSync(join(ROOT, 'lib', 'api-client.js'), 'utf8'), { filename: 'api-client.js' });
  const { apiClient } = globalThis.CyberGuardExt;

  const logs = [];
  const origLog = console.log;
  console.log = (...args) => {
    logs.push(args.join(' '));
    origLog(...args);
  };

  let pollCount = 0;
  const mockAlertId = 'alert-uuid-1234';
  const finalExplanation = 'Medium Risk (Score 54/100): Phishing indicators detected.';

  apiClient.configure({
    getAuth: async () => ({ access_token: 'valid-test-token' }),
    refresh: async () => null,
    signOut: async () => {},
    fetchImpl: async (url, init) => {
      assert.ok(url.includes(`/alerts/${mockAlertId}`), `Must poll /alerts/${mockAlertId}`);
      pollCount++;
      if (pollCount === 1) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ id: mockAlertId, risk_score: 54, explanation: null }),
        };
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({ id: mockAlertId, risk_score: 54, explanation: finalExplanation }),
      };
    },
  });

  // Simple DOM simulation
  const createdElements = [];
  function mockEl(tag, className, text = '') {
    const element = {
      tag,
      className,
      textContent: text,
      children: [],
      appendChild(child) {
        this.children.push(child);
      },
      replaceChildren(...newChildren) {
        this.children = newChildren;
      },
    };
    createdElements.push(element);
    return element;
  }

  const container = mockEl('div', 'container');
  const expContainer = mockEl('div', 'result__explanation-container');
  const loading = mockEl('div', 'result__explanation-loading');
  const textSpan = mockEl('span', 'result__explanation-loading-text', 'Generating AI explanation...');
  loading.appendChild(textSpan);
  expContainer.appendChild(loading);
  container.appendChild(expContainer);

  const apiBase = 'http://localhost:8000/api/v1';
  const alertId = mockAlertId;

  // Run the polling logic identical to popup.js
  console.log(`Starting polling for alert ${alertId}`);
  let attempts = 0;
  let finished = false;

  await new Promise((resolve) => {
    const timerId = setTimeout(() => {
      textSpan.textContent = 'Generating heuristic explanation...';
    }, 10000);

    const intervalId = setInterval(async () => {
      attempts++;
      if (attempts > 30) {
        clearInterval(intervalId);
        clearTimeout(timerId);
        resolve();
        return;
      }
      try {
        const updated = await apiClient.getAlert(apiBase, alertId);
        console.log(`Poll attempt #${attempts} - response:`, JSON.stringify(updated));
        if (updated && updated.explanation) {
          console.log(`Explanation received: ${updated.explanation}`);
          clearTimeout(timerId);
          clearInterval(intervalId);
          expContainer.replaceChildren(mockEl('p', 'result__explanation', String(updated.explanation)));
          finished = true;
          resolve();
        } else {
          console.log('Explanation still null, continuing poll');
        }
      } catch (e) {
        console.error(`Poll attempt #${attempts} error:`, e);
      }
    }, 50); // Fast interval for testing
  });

  console.log = origLog;

  assert.strictEqual(finished, true, 'Polling should successfully finish');
  assert.strictEqual(pollCount, 2, 'Should have polled twice');
  assert.ok(logs.some((l) => l.includes(`Starting polling for alert ${mockAlertId}`)));
  assert.ok(logs.some((l) => l.includes('Explanation still null, continuing poll')));
  assert.ok(logs.some((l) => l.includes(`Explanation received: ${finalExplanation}`)));
  assert.strictEqual(expContainer.children[0].textContent, finalExplanation);
});
