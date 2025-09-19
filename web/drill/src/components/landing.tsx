import { type JSX, useEffect, useMemo, useState } from "react";
import {
  ArrowRightIcon,
  CheckCircledIcon,
  CopyIcon,
  DownloadIcon,
} from "@radix-ui/react-icons";

const DOWNLOAD_DOMAIN = "dl.getexposed.io";
const RELEASES_URL = "https://github.com/DragonSecurity/drill/releases";
const LATEST_RELEASE_API =
  "https://api.github.com/repos/DragonSecurity/drill/releases/latest";

function CopyButton({ text, className }: { text: string; className?: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      const t = setTimeout(() => setCopied(false), 1200);
      return () => clearTimeout(t);
    } catch (e) {
      console.error("Clipboard copy failed", e);
    }
  };

  return (
    <button
      onClick={handleCopy}
      className={
        "inline-flex items-center gap-1 rounded-md border px-2.5 py-1.5 text-xs font-medium shadow-sm transition-colors " +
        (copied
          ? "border-green-200 bg-green-50 text-green-700 hover:bg-green-100 "
          : "border-gray-200 bg-white text-gray-700 hover:bg-gray-50 ") +
        (className ? ` ${className}` : "")
      }
      aria-label={copied ? "Copied" : "Copy to clipboard"}
    >
      {copied ? <CheckCircledIcon /> : <CopyIcon />}
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

function CodeInstall({ label, cmd }: { label: string; cmd: string }) {
  return (
    <div className="group relative w-full max-w-2xl overflow-hidden rounded-xl border border-gray-200 bg-white p-3 shadow-sm sm:p-4">
      <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-gray-500">
        {label}
      </div>
      <div className="flex items-start justify-between gap-3">
        <code className="block w-full select-all whitespace-pre-wrap break-all rounded bg-gray-50 p-3 text-sm text-gray-800 ring-1 ring-inset ring-gray-100">
          {cmd}
        </code>
        <CopyButton text={cmd} className="shrink-0" />
      </div>
    </div>
  );
}

export function Landing(): JSX.Element {
  const [latestTag, setLatestTag] = useState<string | null>(null);
  const [releaseUrl, setReleaseUrl] = useState<string>(RELEASES_URL);
  const [publishedAt, setPublishedAt] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch(LATEST_RELEASE_API, {
          headers: { Accept: "application/vnd.github+json" },
        });
        if (!res.ok) throw new Error("GitHub API error: " + res.status);
        const data = await res.json();
        if (cancelled) return;
        setLatestTag(data.tag_name || data.name || null);
        setReleaseUrl(data.html_url || RELEASES_URL);
        if (data.published_at)
          setPublishedAt(new Date(data.published_at).toLocaleDateString());
      } catch (e) {
        // Silently fall back to static link if rate limited or offline
        console.warn("Failed to fetch latest release", e);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const agentCmd = useMemo(
    () => `/bin/bash -c "$(curl -fsSL https://${DOWNLOAD_DOMAIN}/agent.sh)"`,
    [],
  );
  const serverCmd = useMemo(
    () => `/bin/bash -c "$(curl -fsSL https://${DOWNLOAD_DOMAIN}/server.sh)"`,
    [],
  );

  return (
    <>
      {/* Announcement bar */}
      <div className="mx-auto mb-8 flex max-w-3xl justify-center px-4 sm:px-6">
        <a
          href={releaseUrl}
          target="_blank"
          rel="noreferrer noopener"
          className="relative inline-flex items-center gap-2 rounded-full bg-white px-3 py-1 text-sm leading-6 text-gray-700 ring-1 ring-gray-900/10 transition hover:ring-gray-900/20"
        >
          <span
            className="inline-flex h-2 w-2 rounded-full bg-green-500"
            aria-hidden
          />
          {latestTag ? (
            <>
              <span className="font-semibold">Drill {latestTag}</span>
              <span className="text-gray-500">
                {publishedAt ? `· Released ${publishedAt}` : "· Latest release"}
              </span>
              <span className="ml-1 inline-flex items-center font-medium text-pink-600">
                Download here <span className="ml-1">→</span>
              </span>
            </>
          ) : (
            <>
              <span className="font-semibold">New release available</span>
              <span className="text-gray-500">· Check what’s new</span>
              <span className="ml-1 inline-flex items-center font-medium text-pink-600">
                View on GitHub <span className="ml-1">→</span>
              </span>
            </>
          )}
        </a>
      </div>

      {/* Hero */}
      <section className="px-4 text-center sm:px-6">
        <h1 className="bg-gradient-to-r from-green-500 to-blue-600 bg-clip-text text-4xl font-extrabold tracking-tight text-transparent sm:text-6xl">
          Expose Yourself to the World!
        </h1>
        <p className="mx-auto mt-6 max-w-2xl text-lg leading-8 text-gray-700">
          Behind a NAT and need to share your local service securely?{" "}
          <span className="font-medium">Drill</span> creates production‑grade
          tunnels over SSH in seconds—no agents, no headaches.
        </p>

        {/* Install blocks */}
        <div className="mx-auto mt-10 grid max-w-4xl grid-cols-1 gap-4 sm:gap-5 lg:grid-cols-2">
          <CodeInstall label="Install Agent" cmd={agentCmd} />
          <CodeInstall label="Install Server" cmd={serverCmd} />
        </div>

        {/* CTA buttons */}
        <div className="mt-10 flex flex-wrap items-center justify-center gap-3">
          <a
            href={releaseUrl}
            target="_blank"
            rel="noreferrer noopener"
            className="inline-flex items-center rounded-xl bg-green-600 px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-green-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-green-500"
          >
            Download{latestTag ? ` ${latestTag}` : ""}
            <DownloadIcon className="ml-2" />
          </a>
          <a
            href="https://github.com/DragonSecurity/drill/blob/main/README.md"
            target="_blank"
            rel="noreferrer noopener"
            className="inline-flex items-center rounded-xl border border-gray-200 bg-white px-5 py-3 text-sm font-semibold text-gray-700 shadow-sm transition hover:bg-gray-50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-gray-300"
          >
            Readme
            <ArrowRightIcon className="ml-2" />
          </a>
        </div>

        {/* Small footnote */}
        <p className="mx-auto mt-6 max-w-3xl text-xs text-gray-500">
          Tip: host <code className="rounded bg-gray-100 px-1">agent.sh</code>{" "}
          and <code className="rounded bg-gray-100 px-1">server.sh</code> at{" "}
          <code className="rounded bg-gray-100 px-1">
            https://{DOWNLOAD_DOMAIN}/
          </code>{" "}
          to keep these one‑liners working everywhere.
        </p>
      </section>
    </>
  );
}
