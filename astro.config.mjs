// @ts-check
import { defineConfig } from 'astro/config';
import mdx from '@astrojs/mdx';
import { remarkAlert } from "remark-github-blockquote-alert";

import sitemap from '@astrojs/sitemap';

// https://astro.build/config
export default defineConfig({
	site: 'https://localhost:3000',
	integrations: [mdx(), sitemap()],
	markdown: {
		shikiConfig: {
		  theme: 'vitesse-dark',
		},
		remarkPlugins: [remarkAlert],
	  },
});
