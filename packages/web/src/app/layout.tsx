import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "SolShield AI - AI-Powered Smart Contract Auditor for Solana",
  description: "Detect vulnerabilities in your Anchor programs instantly. Get AI-powered explanations and fix suggestions. Ship secure code faster.",
  keywords: ["Solana", "smart contract", "security", "audit", "Anchor", "Rust", "AI"],
  openGraph: {
    title: "SolShield AI - AI-Powered Smart Contract Auditor",
    description: "Detect vulnerabilities in your Anchor programs instantly.",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        {children}
      </body>
    </html>
  );
}
