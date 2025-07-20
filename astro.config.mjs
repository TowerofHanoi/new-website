// @ts-check
import { defineConfig } from 'astro/config';
import mdx from '@astrojs/mdx';
import { remarkAlert } from "remark-github-blockquote-alert";

import sitemap from '@astrojs/sitemap';

import metaTags from 'astro-meta-tags';

// https://astro.build/config
export default defineConfig({
    site: 'https://towerofhanoi.it',
    integrations: [mdx(), sitemap(), metaTags()],
    markdown: {
        shikiConfig: {
          theme: 'vitesse-dark',
        },
        remarkPlugins: [remarkAlert],
      },
});