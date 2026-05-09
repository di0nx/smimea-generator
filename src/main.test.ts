// @vitest-environment jsdom
import { describe, expect, it } from 'vitest';

describe('application shell', () => {
  it('renders the static UI instead of leaving #app empty', async () => {
    document.body.innerHTML = '<div id="app"></div>';
    localStorage.clear();

    await import('./main');

    expect(document.querySelector('h1')?.textContent).toBe('SMIMEA DNS Record Generator');
    expect(document.querySelector<HTMLInputElement>('#cert')).not.toBeNull();
    expect(document.querySelector<HTMLInputElement>('#checkFqdn')?.placeholder).toContain('example.org');
    expect(document.querySelector<HTMLButtonElement>('#generate')?.textContent).toContain('ausgewählte Adressen');
  });
});
