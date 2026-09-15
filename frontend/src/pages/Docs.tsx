import { useMemo, useState } from 'react';
import {
  BookOpen,
  Building2,
  ChevronRight,
  Copy,
  Check,
  Lock,
  Search,
} from 'lucide-react';
import PageHeader from '../components/common/PageHeader';
import { useAuthStore } from '../store/authStore';
import { DOC_SECTIONS, type DocBlock, type DocSection } from '../docs/content';

const AUDIENCE_BADGES: Record<string, { label: string; cls: string }> = {
  both: { label: 'User + Org', cls: 'bg-zinc-800 text-zinc-300 ring-zinc-600/50' },
  user: { label: 'Personal', cls: 'bg-sky-500/10 text-sky-400 ring-sky-500/30' },
  org: { label: 'Org', cls: 'bg-red-500/10 text-red-400 ring-red-500/30' },
};

function roleSatisfied(minRole: string | undefined, can: (p: 'analyze' | 'mutate' | 'admin') => boolean): boolean {
  if (!minRole || minRole === 'viewer') return true;
  if (minRole === 'analyst') return can('analyze');
  return can('admin');
}

function CodeBlock({ block }: { block: Extract<DocBlock, { kind: 'code' }> }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(block.code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      /* clipboard unavailable — user can select manually */
    }
  };
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-950">
      {block.title && (
        <div className="flex items-center justify-between border-b border-zinc-800/80 px-3.5 py-2">
          <span className="font-mono text-[10px] uppercase tracking-wider text-zinc-500">{block.title}</span>
          <button
            onClick={copy}
            className="inline-flex items-center gap-1 text-[10px] text-zinc-400 transition hover:text-zinc-200"
          >
            {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
            {copied ? 'Copied' : 'Copy'}
          </button>
        </div>
      )}
      {!block.title && (
        <button
          onClick={copy}
          className="float-right m-2 inline-flex items-center gap-1 text-[10px] text-zinc-500 transition hover:text-zinc-300"
        >
          {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
        </button>
      )}
      <pre className="overflow-x-auto p-4 font-mono text-[11px] leading-relaxed text-zinc-300">{block.code}</pre>
      {block.provenance && (
        <p className="border-t border-zinc-800/80 px-3.5 py-1.5 font-mono text-[9px] text-zinc-600">
          provenance: {block.provenance}
        </p>
      )}
    </div>
  );
}

function BlockView({ block }: { block: DocBlock }) {
  if (block.kind === 'text') {
    return <p className="text-xs leading-relaxed text-zinc-300">{block.body}</p>;
  }
  if (block.kind === 'list') {
    return (
      <ul className="list-disc space-y-1 pl-5 text-xs leading-relaxed text-zinc-300">
        {block.items.map((item, i) => <li key={i}>{item}</li>)}
      </ul>
    );
  }
  if (block.kind === 'code') return <CodeBlock block={block} />;
  if (block.kind === 'diagram') {
    return (
      <div className="rounded-lg border border-zinc-800 bg-zinc-950">
        {block.title && (
          <div className="border-b border-zinc-800/80 px-3.5 py-2 font-mono text-[10px] uppercase tracking-wider text-red-400">
            {block.title}
          </div>
        )}
        <pre className="overflow-x-auto p-4 font-mono text-[11px] leading-relaxed text-zinc-300">{block.code}</pre>
      </div>
    );
  }
  return (
    <div className="overflow-x-auto rounded-lg border border-zinc-800">
      <table className="w-full text-left text-xs">
        <thead className="border-b border-zinc-800 bg-zinc-950/80 font-mono uppercase tracking-wider text-zinc-500">
          <tr>{block.headers.map((h) => <th key={h} className="px-3 py-2">{h}</th>)}</tr>
        </thead>
        <tbody className="divide-y divide-zinc-800/70">
          {block.rows.map((row, i) => (
            <tr key={i} className="text-zinc-300">
              {row.map((cell, j) => <td key={j} className="px-3 py-2 align-top">{cell}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * ORG-5: in-app dynamic documentation. Content lives in src/docs/content.ts
 * (provenance-tracked); this page renders it with a sticky TOC, search, and
 * audience/role gating. In a personal workspace, org-audience sections are
 * badged "Organization feature"; minRole sections render a reduced set.
 */
export default function Docs() {
  const [query, setQuery] = useState('');
  const can = useAuthStore((s) => s.can);
  const activeOrganization = useAuthStore((s) => s.activeOrganization);
  const isOrgWorkspace = Boolean(activeOrganization && !activeOrganization.is_personal);

  const sections = useMemo(() => {
    const q = query.trim().toLowerCase();
    return DOC_SECTIONS.filter((s) => {
      if (!roleSatisfied(s.minRole, can)) return false;
      if (!q) return true;
      const haystack = [s.title, s.summary, ...s.body.map((b) => JSON.stringify(b))]
        .join(' ')
        .toLowerCase();
      return haystack.includes(q);
    });
  }, [query, can]);

  return (
    <div className="flex gap-6">
      {/* Sticky TOC */}
      <aside className="sticky top-6 hidden h-fit w-64 shrink-0 lg:block">
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/90 p-4 backdrop-blur">
          <div className="mb-3 flex items-center gap-2 font-mono text-[10px] font-bold uppercase tracking-wider text-zinc-400">
            <BookOpen className="h-3.5 w-3.5 text-red-400" /> Contents
          </div>
          <nav className="space-y-1">
            {sections.map((s) => (
              <a
                key={s.id}
                href={`#doc-${s.id}`}
                className="flex items-center gap-1.5 rounded px-2 py-1.5 text-[11px] text-zinc-400 transition hover:bg-zinc-800/60 hover:text-zinc-200"
              >
                <ChevronRight className="h-3 w-3 shrink-0 text-zinc-600" />
                <span className="truncate">{s.title}</span>
              </a>
            ))}
            {sections.length === 0 && <p className="px-2 py-1 text-[11px] text-zinc-600">No matches</p>}
          </nav>
        </div>
      </aside>

      {/* Main content */}
      <div className="min-w-0 flex-1 space-y-6">
        <PageHeader
          title="Documentation"
          description="Feature guides, architecture, and API reference — generated from the real system, provenance-tracked."
        />

        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-600" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search docs — titles and bodies (e.g. quarantine, min_role, RLS)…"
            className="w-full rounded-xl border border-zinc-800 bg-zinc-900/90 py-2.5 pl-10 pr-4 text-xs text-zinc-100 placeholder-zinc-500 outline-none backdrop-blur focus:border-red-500/60"
          />
        </div>

        {sections.map((section) => (
          <SectionArticle key={section.id} section={section} isOrgWorkspace={isOrgWorkspace} />
        ))}
        {sections.length === 0 && (
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/90 p-8 text-center text-xs text-zinc-500">
            No documentation matches "{query}".
          </div>
        )}
      </div>
    </div>
  );
}

function SectionArticle({ section, isOrgWorkspace }: { section: DocSection; isOrgWorkspace: boolean }) {
  const badge = AUDIENCE_BADGES[section.audience];
  const showOrgBadge = section.audience === 'org' && !isOrgWorkspace;
  return (
    <article id={`doc-${section.id}`} className="scroll-mt-6 space-y-4 rounded-xl border border-zinc-800 bg-zinc-900/90 p-5 backdrop-blur">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-sm font-bold text-zinc-100">{section.title}</h2>
        <span className={`rounded-full px-2 py-0.5 font-mono text-[9px] uppercase tracking-wider ring-1 ${badge.cls}`}>
          {badge.label}
        </span>
        {showOrgBadge && (
          <span className="inline-flex items-center gap-1 rounded-full bg-amber-500/10 px-2 py-0.5 font-mono text-[9px] uppercase tracking-wider text-amber-400 ring-1 ring-amber-500/30">
            <Building2 className="h-3 w-3" /> Organization feature
          </span>
        )}
        {section.minRole && section.minRole !== 'viewer' && (
          <span className="inline-flex items-center gap-1 rounded-full bg-zinc-800 px-2 py-0.5 font-mono text-[9px] uppercase tracking-wider text-zinc-400 ring-1 ring-zinc-600/50">
            <Lock className="h-3 w-3" /> {section.minRole}+
          </span>
        )}
      </div>
      <p className="text-xs italic text-zinc-500">{section.summary}</p>
      <div className="space-y-3">
        {section.body.map((block, i) => <BlockView key={i} block={block} />)}
      </div>
    </article>
  );
}
