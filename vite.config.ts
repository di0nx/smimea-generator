import { defineConfig } from 'vite';

export default defineConfig({
  // Use relative asset URLs so the static build also works from GitHub Pages
  // project subpaths on static hosting.
  base: './',
});
