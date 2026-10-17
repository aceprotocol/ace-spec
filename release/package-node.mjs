/** Assemble publishable packages without leaking checkout paths. Does not publish to a registry. */
import { cp, mkdir, mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const output = resolve(process.argv[2] ?? '/tmp/ace-release-candidate/node');
await mkdir(output, { recursive: true });
const names = ['sdk-ts', 'ace-cli', 'relay', 'ace-mcp'];
const packages = new Map(await Promise.all(names.map(async n => [n, JSON.parse(await readFile(join(root,n,'package.json'),'utf8'))])));
const byName = new Map([...packages.values()].map(p => [p.name, p]));
const EXTRAS = ['resources','openapi.yaml','LICENSE','README.md'];
const manifest = [];
for (const name of names) {
  const dir = join(root, name), source = packages.get(name);
  execFileSync('git', ['diff', '--exit-code', 'HEAD', '--'], { cwd: dir, stdio: 'pipe' });
  const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: dir, encoding: 'utf8' }).trim();
  const stage = await mkdtemp(join(tmpdir(),'ace-package-'));
  try {
    const pkg = structuredClone(source);
    for (const group of ['dependencies','optionalDependencies','devDependencies']) {
      for (const [dep, version] of Object.entries(pkg[group] ?? {})) {
        if (!version.startsWith('file:')) continue;
        const target = byName.get(dep);
        if (group === 'devDependencies') delete pkg[group][dep];
        else if (target) pkg[group][dep] = target.version;
        else throw new Error(`unresolved local dependency ${name}:${dep}`);
      }
    }
    pkg.files = ['dist', ...EXTRAS];
    delete pkg.scripts;
    await cp(join(dir,'dist'),join(stage,'dist'),{recursive:true});
    for (const file of EXTRAS) {
      try { await cp(join(dir,file),join(stage,file),{recursive:true}); } catch(e) { if(e.code !== 'ENOENT') throw e; }
    }
    const json = JSON.stringify(pkg,null,2)+'\n';
    await writeFile(join(stage,'package.json'),json);
    // TypeScript copies package metadata imported by binaries into dist. Keep it normalized too.
    if (existsSync(join(stage,'dist/package.json'))) await writeFile(join(stage,'dist/package.json'),json);
    const packed = JSON.parse(execFileSync('npm',['pack','--ignore-scripts','--json','--pack-destination',output],{cwd:stage,encoding:'utf8'}))[0];
    const bytes=await readFile(join(output,packed.filename));
    manifest.push({repository:name,commit,package:pkg.name,version:pkg.version,file:packed.filename,sha256:createHash('sha256').update(bytes).digest('hex')});
  } finally { await rm(stage,{recursive:true,force:true}); }
}
await writeFile(join(output,'manifest.json'),JSON.stringify(manifest,null,2)+'\n');
console.log(JSON.stringify({output,packages:manifest},null,2));
