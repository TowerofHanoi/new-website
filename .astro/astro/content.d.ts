declare module 'astro:content' {
	interface Render {
		'.mdx': Promise<{
			Content: import('astro').MarkdownInstance<{}>['Content'];
			headings: import('astro').MarkdownHeading[];
			remarkPluginFrontmatter: Record<string, any>;
			components: import('astro').MDXInstance<{}>['components'];
		}>;
	}
}

declare module 'astro:content' {
	interface RenderResult {
		Content: import('astro/runtime/server/index.js').AstroComponentFactory;
		headings: import('astro').MarkdownHeading[];
		remarkPluginFrontmatter: Record<string, any>;
	}
	interface Render {
		'.md': Promise<RenderResult>;
	}

	export interface RenderedContent {
		html: string;
		metadata?: {
			imagePaths: Array<string>;
			[key: string]: unknown;
		};
	}
}

declare module 'astro:content' {
	type Flatten<T> = T extends { [K: string]: infer U } ? U : never;

	export type CollectionKey = keyof AnyEntryMap;
	export type CollectionEntry<C extends CollectionKey> = Flatten<AnyEntryMap[C]>;

	export type ContentCollectionKey = keyof ContentEntryMap;
	export type DataCollectionKey = keyof DataEntryMap;

	type AllValuesOf<T> = T extends any ? T[keyof T] : never;
	type ValidContentEntrySlug<C extends keyof ContentEntryMap> = AllValuesOf<
		ContentEntryMap[C]
	>['slug'];

	/** @deprecated Use `getEntry` instead. */
	export function getEntryBySlug<
		C extends keyof ContentEntryMap,
		E extends ValidContentEntrySlug<C> | (string & {}),
	>(
		collection: C,
		// Note that this has to accept a regular string too, for SSR
		entrySlug: E,
	): E extends ValidContentEntrySlug<C>
		? Promise<CollectionEntry<C>>
		: Promise<CollectionEntry<C> | undefined>;

	/** @deprecated Use `getEntry` instead. */
	export function getDataEntryById<C extends keyof DataEntryMap, E extends keyof DataEntryMap[C]>(
		collection: C,
		entryId: E,
	): Promise<CollectionEntry<C>>;

	export function getCollection<C extends keyof AnyEntryMap, E extends CollectionEntry<C>>(
		collection: C,
		filter?: (entry: CollectionEntry<C>) => entry is E,
	): Promise<E[]>;
	export function getCollection<C extends keyof AnyEntryMap>(
		collection: C,
		filter?: (entry: CollectionEntry<C>) => unknown,
	): Promise<CollectionEntry<C>[]>;

	export function getEntry<
		C extends keyof ContentEntryMap,
		E extends ValidContentEntrySlug<C> | (string & {}),
	>(entry: {
		collection: C;
		slug: E;
	}): E extends ValidContentEntrySlug<C>
		? Promise<CollectionEntry<C>>
		: Promise<CollectionEntry<C> | undefined>;
	export function getEntry<
		C extends keyof DataEntryMap,
		E extends keyof DataEntryMap[C] | (string & {}),
	>(entry: {
		collection: C;
		id: E;
	}): E extends keyof DataEntryMap[C]
		? Promise<DataEntryMap[C][E]>
		: Promise<CollectionEntry<C> | undefined>;
	export function getEntry<
		C extends keyof ContentEntryMap,
		E extends ValidContentEntrySlug<C> | (string & {}),
	>(
		collection: C,
		slug: E,
	): E extends ValidContentEntrySlug<C>
		? Promise<CollectionEntry<C>>
		: Promise<CollectionEntry<C> | undefined>;
	export function getEntry<
		C extends keyof DataEntryMap,
		E extends keyof DataEntryMap[C] | (string & {}),
	>(
		collection: C,
		id: E,
	): E extends keyof DataEntryMap[C]
		? Promise<DataEntryMap[C][E]>
		: Promise<CollectionEntry<C> | undefined>;

	/** Resolve an array of entry references from the same collection */
	export function getEntries<C extends keyof ContentEntryMap>(
		entries: {
			collection: C;
			slug: ValidContentEntrySlug<C>;
		}[],
	): Promise<CollectionEntry<C>[]>;
	export function getEntries<C extends keyof DataEntryMap>(
		entries: {
			collection: C;
			id: keyof DataEntryMap[C];
		}[],
	): Promise<CollectionEntry<C>[]>;

	export function render<C extends keyof AnyEntryMap>(
		entry: AnyEntryMap[C][string],
	): Promise<RenderResult>;

	export function reference<C extends keyof AnyEntryMap>(
		collection: C,
	): import('astro/zod').ZodEffects<
		import('astro/zod').ZodString,
		C extends keyof ContentEntryMap
			? {
					collection: C;
					slug: ValidContentEntrySlug<C>;
				}
			: {
					collection: C;
					id: keyof DataEntryMap[C];
				}
	>;
	// Allow generic `string` to avoid excessive type errors in the config
	// if `dev` is not running to update as you edit.
	// Invalid collection names will be caught at build time.
	export function reference<C extends string>(
		collection: C,
	): import('astro/zod').ZodEffects<import('astro/zod').ZodString, never>;

	type ReturnTypeOrOriginal<T> = T extends (...args: any[]) => infer R ? R : T;
	type InferEntrySchema<C extends keyof AnyEntryMap> = import('astro/zod').infer<
		ReturnTypeOrOriginal<Required<ContentConfig['collections'][C]>['schema']>
	>;

	type ContentEntryMap = {
		"blog": {
"2024-11-20-a-new-website.md": {
	id: "2024-11-20-a-new-website.md";
  slug: "2024-11-20-a-new-website";
  body: string;
  collection: "blog";
  data: InferEntrySchema<"blog">
} & { render(): Render[".md"] };
"2024-12-01-anniversary.md": {
	id: "2024-12-01-anniversary.md";
  slug: "2024-12-01-anniversary";
  body: string;
  collection: "blog";
  data: InferEntrySchema<"blog">
} & { render(): Render[".md"] };
"2025-06-27-toh-ctf-25.md": {
	id: "2025-06-27-toh-ctf-25.md";
  slug: "2025-06-27-toh-ctf-25";
  body: string;
  collection: "blog";
  data: InferEntrySchema<"blog">
} & { render(): Render[".md"] };
};
"writeups": {
"2015-06-12-PNG_Uncorrupt.md": {
	id: "2015-06-12-PNG_Uncorrupt.md";
  slug: "2015-06-12-png_uncorrupt";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"2015-07-12-Exceptionally-obfuscated.md": {
	id: "2015-07-12-Exceptionally-obfuscated.md";
  slug: "2015-07-12-exceptionally-obfuscated";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"2015-07-12-Lightning.md": {
	id: "2015-07-12-Lightning.md";
  slug: "2015-07-12-lightning";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"2015-07-13-Server-lies.md": {
	id: "2015-07-13-Server-lies.md";
  slug: "2015-07-13-server-lies";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"2015-09-23-Airport.md": {
	id: "2015-09-23-Airport.md";
  slug: "2015-09-23-airport";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"2015-09-24-Autobots.md": {
	id: "2015-09-24-Autobots.md";
  slug: "2015-09-24-autobots";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"2015-10-05-DCTF_2015_Web.md": {
	id: "2015-10-05-DCTF_2015_Web.md";
  slug: "2015-10-05-dctf_2015_web";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"2015-10-24-StackStuff.md": {
	id: "2015-10-24-StackStuff.md";
  slug: "2015-10-24-stackstuff";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"2016-01-18-smartcat.md": {
	id: "2016-01-18-smartcat.md";
  slug: "2016-01-18-smartcat";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"2016-05-23-Pound.md": {
	id: "2016-05-23-Pound.md";
  slug: "2016-05-23-pound";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"2016-05-31-Heapfun4u.md": {
	id: "2016-05-31-Heapfun4u.md";
  slug: "2016-05-31-heapfun4u";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"2016-10-10-ROP.md": {
	id: "2016-10-10-ROP.md";
  slug: "2016-10-10-rop";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"2017-07-08-Pasticciotto.md": {
	id: "2017-07-08-Pasticciotto.md";
  slug: "2017-07-08-pasticciotto";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"2017-07-10-EzWinShell.md": {
	id: "2017-07-10-EzWinShell.md";
  slug: "2017-07-10-ezwinshell";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"2017-07-11-PowderToy-CPU.md": {
	id: "2017-07-11-PowderToy-CPU.md";
  slug: "2017-07-11-powdertoy-cpu";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"2017-07-12-Lamermi.md": {
	id: "2017-07-12-Lamermi.md";
  slug: "2017-07-12-lamermi";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"2017-11-08-Secret_Server.md": {
	id: "2017-11-08-Secret_Server.md";
  slug: "2017-11-08-secret_server";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"2017-11-08-Secret_Server_Revenge.md": {
	id: "2017-11-08-Secret_Server_Revenge.md";
  slug: "2017-11-08-secret_server_revenge";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"2018-04-15-Ribbons.md": {
	id: "2018-04-15-Ribbons.md";
  slug: "2018-04-15-ribbons";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"2018-10-18-Forgetful_Commander.md": {
	id: "2018-10-18-Forgetful_Commander.md";
  slug: "2018-10-18-forgetful_commander";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"2019-04-30-Brainhugger.md": {
	id: "2019-04-30-Brainhugger.md";
  slug: "2019-04-30-brainhugger";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"2021-10-28-Intigriti-0321.md": {
	id: "2021-10-28-Intigriti-0321.md";
  slug: "2021-10-28-intigriti-0321";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"2021-12-14-XMAS-CTF.md": {
	id: "2021-12-14-XMAS-CTF.md";
  slug: "2021-12-14-xmas-ctf";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"2021-12-18-CaramelPooler.md": {
	id: "2021-12-18-CaramelPooler.md";
  slug: "2021-12-18-caramelpooler";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"2021-12-22-horrorscope.md": {
	id: "2021-12-22-horrorscope.md";
  slug: "2021-12-22-horrorscope";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"2021-12-27-Intigriti-1221.md": {
	id: "2021-12-27-Intigriti-1221.md";
  slug: "2021-12-27-intigriti-1221";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"2022-08-15-UIUCTF-2022-SMM-Cowsay.md": {
	id: "2022-08-15-UIUCTF-2022-SMM-Cowsay.md";
  slug: "2022-08-15-uiuctf-2022-smm-cowsay";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"2022-10-31-Reply2022.md": {
	id: "2022-10-31-Reply2022.md";
  slug: "2022-10-31-reply2022";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"2024-11-10-HKCERT-QUALS-Black-magic.md": {
	id: "2024-11-10-HKCERT-QUALS-Black-magic.md";
  slug: "2024-11-10-hkcert-quals-black-magic";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"2025-03-14-sudo-kurl.md": {
	id: "2025-03-14-sudo-kurl.md";
  slug: "2025-03-14-sudo-kurl";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
"CVE-2025-1550.md": {
	id: "CVE-2025-1550.md";
  slug: "cve-2025-1550";
  body: string;
  collection: "writeups";
  data: InferEntrySchema<"writeups">
} & { render(): Render[".md"] };
};

	};

	type DataEntryMap = {
		
	};

	type AnyEntryMap = ContentEntryMap & DataEntryMap;

	export type ContentConfig = typeof import("../../src/content/config.js");
}
