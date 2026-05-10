// @vitest-environment jsdom
import { describe, expect, it } from 'vitest';

describe('application shell', () => {
  it('renders the minimal multi-page UI instead of leaving #app empty', async () => {
    document.body.innerHTML = '<div id="app"></div>';
    localStorage.clear();

    await import('./main');

    expect(document.querySelector('.brand b')?.textContent).toBe('SMIMEA');
    expect(document.querySelector<HTMLAnchorElement>('a[href="#/check"]')?.textContent).toBe('Record Check');
    expect(document.querySelector('#checkPage h1')?.textContent).toContain('Zertifikat herunterladen');
    expect(document.querySelector<HTMLInputElement>('#cert')).not.toBeNull();
    expect(document.querySelector<HTMLSelectElement>('#cfTransport')?.value).toBe('proxy');
    expect(document.querySelector<HTMLInputElement>('#checkEmail')?.placeholder).toContain('email-address');
    expect(document.querySelector<HTMLButtonElement>('#generate')?.textContent).toContain('Records erzeugen');
  });
});
