# App router notes

## There is deliberately no root `loading.tsx`

A root-level `loading.tsx` wraps every route in a Suspense boundary, which makes
Next.js begin streaming the response — and commit an HTTP 200 — before any of
the page's async work has run. Once that has happened, `notFound()` still renders
the correct not-found UI, but the status code is already sent.

The result is `/scans/{unknown-id}` returning **200 OK** with "Not found" in the
body. That breaks caching, uptime monitoring, link checkers and any CI step that
treats a non-2xx as a failure — and for a tool whose whole job is producing
trustworthy signals, a lying status code is not an acceptable trade for a
skeleton screen.

Verified in a production build:

| Route                        | With root `loading.tsx` | Without |
| ---------------------------- | ----------------------- | ------- |
| `/scans/{unknown}`           | 200                     | **404** |
| `/projects/{unknown}`        | 200                     | **404** |
| `/no-such-page`              | 404                     | 404     |

The existence checks additionally live in `generateMetadata`, which Next awaits
before rendering begins, so the 404 is decided as early as possible.

If a loading state is wanted for a specific slow route in future, add
`loading.tsx` inside that segment only — never at the root, and never above a
segment that can legitimately 404.
