// security-baseline Astro/TS rule self-test fixture — JSX-only rule (tsx).
// Run: semgrep --test --config rules/astro-ts.yaml rules/selftest/astro-ts.tsx
declare const DOMPurify: any;

export function BioBad({ user }: { user: { bioHtml: string } }) {
  // ruleid: ts-dangerous-html-untrusted
  return <div dangerouslySetInnerHTML={{ __html: user.bioHtml }} />;
}

export function BioOk({ user }: { user: { bioHtml: string } }) {
  // ok: ts-dangerous-html-untrusted
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(user.bioHtml) }} />;
}
