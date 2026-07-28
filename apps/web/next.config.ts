import type { NextConfig } from 'next';

const config: NextConfig = {
  reactStrictMode: true,

  // The workspace packages ship TypeScript source; Next compiles them with the
  // app so there is no separate build step during development.
  transpilePackages: [
    '@sentinel/core',
    '@sentinel/scanners',
    '@sentinel/ai',
    '@sentinel/reports',
    '@sentinel/platform',
  ],

  // Scanners spawn processes and read the filesystem, and the SQLite driver is
  // a native binding — none of that can be bundled.
  serverExternalPackages: ['node:sqlite', 'postgres', 'ioredis', '@clerk/backend'],

  // The workspace packages are NodeNext modules, so their relative imports carry
  // a `.js` extension even though the files on disk are `.ts`. Both bundlers
  // need to be told to try the TypeScript source for those specifiers.
  webpack(config) {
    config.resolve.extensionAlias = {
      ...config.resolve.extensionAlias,
      '.js': ['.ts', '.tsx', '.js'],
    };

    // The platform package loads optional adapters (Postgres, Redis, Clerk,
    // node:sqlite) through a variable specifier so they stay genuinely
    // optional. Webpack cannot statically analyze that by design, so its
    // "critical dependency" warning is expected rather than a defect.
    config.ignoreWarnings = [...(config.ignoreWarnings ?? []), { module: /optional-import\.ts$/ }];

    return config;
  },

  turbopack: {
    resolveExtensions: ['.ts', '.tsx', '.mts', '.js', '.jsx', '.mjs', '.json'],
  },

  eslint: {
    // Linting is a separate, required CI step (`pnpm lint`), so duplicating it
    // here only doubles build time. Sentinel flags this correctly as a weakened
    // build-time check; the compensating control is that CI gates on lint
    // independently and a failing lint blocks the merge.
    // sentinel-disable-next-line config-nextjs-ignore-errors
    ignoreDuringBuilds: true,
  },

  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          // Defense in depth for a dashboard that renders untrusted repository
          // content (file paths, code snippets, dependency names).
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          {
            key: 'Permissions-Policy',
            value: 'camera=(), microphone=(), geolocation=(), payment=()',
          },
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=31536000; includeSubDomains',
          },
        ],
      },
    ];
  },
};

export default config;
