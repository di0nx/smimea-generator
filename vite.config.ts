import { defineConfig } from 'vite';

export default defineConfig({
  // Use relative asset URLs so the static build also works from GitHub Pages
  // project subpaths such as https://user.github.io/smimea-generator/.
  base: './',
});
