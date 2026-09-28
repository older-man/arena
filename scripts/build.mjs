import { build } from 'esbuild';
import { mkdir, copyFile } from 'node:fs/promises';
await mkdir('dist/extension',{recursive:true});
await build({entryPoints:['extension/background.ts','extension/content.ts','extension/popup.ts'],bundle:true,outdir:'dist/extension',format:'iife',target:'chrome120'});
for(const file of ['manifest.json','popup.html','popup.css']) await copyFile(`extension/${file}`,`dist/extension/${file}`);
await build({entryPoints:['desktop/renderer.ts'],bundle:true,outfile:'desktop/renderer.js',format:'iife',target:'chrome120'});
