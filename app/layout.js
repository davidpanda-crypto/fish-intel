import './globals.css';

export const metadata = {
  title:       'Fish Farm & Ship Intelligence',
  description: 'Research fish farms, mills & vessels — locations, species, certifications, maritime records',
  robots:      'noindex',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <head>
        <meta httpEquiv="Content-Security-Policy"
          content="default-src 'self' 'unsafe-inline' https: data: blob:; img-src * data: blob:; connect-src *;" />
        <meta name="referrer" content="no-referrer" />
        {/* DOMPurify — needed before app.js */}
        <script
          src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/3.0.6/purify.min.js"
          crossOrigin="anonymous"
          referrerPolicy="no-referrer"
        />
        {/* Fonts */}
        <link
          href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;700;900&family=Libre+Franklin:wght@300;400;500;600;700&display=swap"
          rel="stylesheet"
        />
        {/* App CSS */}
        <link rel="stylesheet" href="/css/style.css" />
      </head>
      <body>{children}</body>
    </html>
  );
}
