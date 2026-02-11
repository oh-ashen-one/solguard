import type { Metadata } from "next";
import { Inter, Space_Grotesk, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
});

const spaceGrotesk = Space_Grotesk({
  variable: "--font-space",
  subsets: ["latin"],
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "SolShield — AI-Powered Solana Smart Contract Security Audit Tool",
  description: "Free Solana smart contract audit tool with 7,000+ vulnerability patterns. Detect security flaws in Anchor programs and vibe-coded Rust instantly. No signup required.",
  keywords: ["solana smart contract audit", "solana security scanner", "anchor program audit", "vibe coded crypto security", "solana vulnerability detector", "rust smart contract security", "AI code audit", "SolShield"],
  authors: [{ name: "Ashen One", url: "https://www.youtube.com/@ashenonesol" }],
  robots: "index, follow",
  alternates: {
    canonical: "https://solshieldai.netlify.app",
  },
  openGraph: {
    title: "SolShield — AI-Powered Solana Smart Contract Security Audit",
    description: "Free Solana smart contract audit tool with 7,000+ vulnerability patterns. Detect security flaws in Anchor programs and vibe-coded Rust instantly.",
    type: "website",
    url: "https://solshieldai.netlify.app",
  },
  twitter: {
    card: "summary_large_image",
    title: "SolShield — Solana Smart Contract Security Scanner",
    description: "Free AI-powered security audits for Solana smart contracts. 7,000+ vulnerability patterns from real exploits. Built for the vibe coding era.",
    creator: "@ashen_one",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="scroll-smooth">
      <head>
        <script async src="https://www.googletagmanager.com/gtag/js?id=G-234VGQV3K0"></script>
        <script
          dangerouslySetInnerHTML={{
            __html: `
              window.dataLayer = window.dataLayer || [];
              function gtag(){dataLayer.push(arguments);}
              gtag('js', new Date());
              gtag('config', 'G-234VGQV3K0');
            `
          }}
        />
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{
            __html: JSON.stringify({
              "@context": "https://schema.org",
              "@type": "SoftwareApplication",
              "name": "SolShield",
              "description": "Free AI-powered Solana smart contract security audit tool with 7,000+ vulnerability patterns from real exploits.",
              "url": "https://solshieldai.netlify.app",
              "applicationCategory": "DeveloperApplication",
              "operatingSystem": "Web",
              "offers": { "@type": "Offer", "price": "0", "priceCurrency": "USD" },
              "author": { "@type": "Person", "name": "Ashen One", "url": "https://www.youtube.com/@ashenonesol" }
            })
          }}
        />
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{
            __html: JSON.stringify({
              "@context": "https://schema.org",
              "@type": "FAQPage",
              "mainEntity": [
                {
                  "@type": "Question",
                  "name": "What is SolShield?",
                  "acceptedAnswer": {
                    "@type": "Answer",
                    "text": "SolShield is a free AI-powered security audit tool for Solana smart contracts. It scans Anchor programs and Rust code against 7,000+ vulnerability patterns derived from real exploits, detecting issues like missing signer checks, integer overflow, PDA validation errors, and reentrancy vulnerabilities. According to DeFiLlama, over $3 billion has been lost to DeFi exploits since 2020."
                  }
                },
                {
                  "@type": "Question",
                  "name": "How does SolShield audit Solana smart contracts?",
                  "acceptedAnswer": {
                    "@type": "Answer",
                    "text": "Paste your Solana program code, upload a file, or link a GitHub repository. SolShield analyzes the code using pattern matching against 7,000+ known vulnerability signatures, including missing owner checks, unsafe arithmetic, improper PDA derivation, and account validation gaps. Results include severity ratings (Critical, High, Medium, Low) with specific code locations and remediation suggestions."
                  }
                },
                {
                  "@type": "Question",
                  "name": "Is SolShield free to use?",
                  "acceptedAnswer": {
                    "@type": "Answer",
                    "text": "Yes, SolShield is completely free with no signup required. The tool runs security analysis and provides detailed vulnerability reports at no cost. It was built for the vibe coding era where developers use AI to generate smart contract code that may contain hidden security flaws."
                  }
                },
                {
                  "@type": "Question",
                  "name": "What types of Solana vulnerabilities does SolShield detect?",
                  "acceptedAnswer": {
                    "@type": "Answer",
                    "text": "SolShield detects critical Solana-specific vulnerabilities including missing signer checks, missing owner checks, integer overflow/underflow, PDA derivation errors, reentrancy attacks, unsafe deserialization, missing rent-exempt checks, unchecked arithmetic, account confusion attacks, and improper close account handling. It covers vulnerabilities specific to Anchor framework programs as well as native Solana Rust programs."
                  }
                }
              ]
            })
          }}
        />
      </head>
      <body
        className={`${inter.variable} ${spaceGrotesk.variable} ${jetbrainsMono.variable} antialiased`}
      >
        {children}
      </body>
    </html>
  );
}
