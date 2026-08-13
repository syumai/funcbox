"use client";

import { useState } from "react";

// A client component: vinext ships this to the browser as a separate chunk
// and hydrates it in place after the server-rendered HTML loads. Clicking
// the buttons only works once that chunk has loaded and hydration has run
// — see the "client JS asset" check in the example's README for how to
// confirm the chunk is actually served.
export function Counter() {
  const [count, setCount] = useState(0);

  return (
    <div className="flex items-center gap-3 rounded-lg border border-slate-200 bg-white p-5">
      <button
        className="rounded-md border border-slate-300 px-3 py-1 text-lg font-semibold hover:bg-slate-100"
        onClick={() => setCount((c) => c - 1)}
        type="button"
      >
        -
      </button>
      <span className="min-w-[3ch] text-center text-lg font-semibold" data-testid="counter-value">
        {count}
      </span>
      <button
        className="rounded-md border border-slate-300 px-3 py-1 text-lg font-semibold hover:bg-slate-100"
        onClick={() => setCount((c) => c + 1)}
        type="button"
      >
        +
      </button>
      <span className="text-sm text-slate-600">client component, hydrated in the browser</span>
    </div>
  );
}
