// Server component: a second route, distinct from "/", so the example can
// demonstrate SSR of more than one page (see the README's verification
// section for the curl checks against both routes).
export default function About() {
  return (
    <main className="min-h-screen bg-slate-50 px-6 py-10 text-slate-950">
      <section className="mx-auto flex max-w-4xl flex-col gap-6">
        <h1 className="text-3xl font-semibold">About this example</h1>
        <p className="max-w-2xl text-lg leading-8 text-slate-700">
          This page is a plain server component rendered on every request by
          vinext's App Router. It doesn't ship any client JavaScript of its
          own — unlike the counter on the home page, there is nothing to
          hydrate here.
        </p>
        <p className="max-w-2xl text-sm text-slate-600">
          Rendered at: <span data-testid="rendered-at">{new Date().toISOString()}</span>
        </p>
        <a
          className="w-fit rounded-md border border-slate-300 bg-white px-4 py-2 text-sm font-medium hover:bg-slate-100"
          href="/"
        >
          Back home
        </a>
      </section>
    </main>
  );
}
