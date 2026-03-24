import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  assertFalOrigin,
  getFalRequestStatus,
  getFalRequestResult,
} from "@/lib/plugins/media-generators/fal";

// ── assertFalOrigin unit tests ──────────────────────────────────────────────

describe("assertFalOrigin", () => {
  describe("allows legitimate Fal.ai URLs", () => {
    it("accepts queue.fal.run status URL", () => {
      expect(() =>
        assertFalOrigin(
          "https://queue.fal.run/fal-ai/flux-pro/v1.1-ultra/requests/abc123/status"
        )
      ).not.toThrow();
    });

    it("accepts queue.fal.run response URL", () => {
      expect(() =>
        assertFalOrigin(
          "https://queue.fal.run/fal-ai/flux-pro/v1.1-ultra/requests/abc123"
        )
      ).not.toThrow();
    });

    it("accepts fal.run URL", () => {
      expect(() =>
        assertFalOrigin("https://fal.run/fal-ai/some-model/requests/xyz")
      ).not.toThrow();
    });
  });

  describe("blocks attacker-controlled URLs", () => {
    it("rejects arbitrary HTTPS domain", () => {
      expect(() =>
        assertFalOrigin("https://evil.com/steal-key")
      ).toThrow("untrusted origin");
    });

    it("rejects Burp Collaborator / OOB exfil domain", () => {
      expect(() =>
        assertFalOrigin(
          "https://176cdvvq1469qvv1vo1x5zw57wdn1fp4.oastify.com/status"
        )
      ).toThrow("untrusted origin");
    });

    it("rejects HTTP (non-TLS) even for fal.run", () => {
      expect(() =>
        assertFalOrigin(
          "http://queue.fal.run/fal-ai/flux-pro/requests/abc123/status"
        )
      ).toThrow("untrusted origin");
    });

    it("rejects subdomain impersonation (evil-fal.run)", () => {
      expect(() =>
        assertFalOrigin("https://evil-fal.run/requests/abc123/status")
      ).toThrow("untrusted origin");
    });

    it("rejects subdomain prefix attack (queue.fal.run.evil.com)", () => {
      expect(() =>
        assertFalOrigin(
          "https://queue.fal.run.evil.com/fal-ai/requests/abc123/status"
        )
      ).toThrow("untrusted origin");
    });

    it("rejects attacker subdomain of fal.run (evil.queue.fal.run)", () => {
      expect(() =>
        assertFalOrigin(
          "https://evil.queue.fal.run/fal-ai/requests/abc123/status"
        )
      ).toThrow("untrusted origin");
    });

    it("rejects internal/localhost SSRF", () => {
      expect(() =>
        assertFalOrigin("https://127.0.0.1/status")
      ).toThrow("untrusted origin");
    });

    it("rejects file:// protocol", () => {
      expect(() =>
        assertFalOrigin("file:///etc/passwd")
      ).toThrow("untrusted origin");
    });

    it("rejects completely invalid URL", () => {
      expect(() => assertFalOrigin("not-a-url")).toThrow("Invalid Fal.ai URL");
    });

    it("rejects empty string", () => {
      expect(() => assertFalOrigin("")).toThrow("Invalid Fal.ai URL");
    });

    it("rejects URL with credentials (userinfo) pointing to attacker", () => {
      expect(() =>
        assertFalOrigin("https://queue.fal.run@evil.com/status")
      ).toThrow("untrusted origin");
    });
  });
});

// ── Integration: getFalRequestStatus / getFalRequestResult reject bad URLs ──

describe("getFalRequestStatus SSRF protection", () => {
  const originalEnv = process.env.FAL_API_KEY;

  beforeEach(() => {
    process.env.FAL_API_KEY = "fk-test-key";
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ status: "IN_QUEUE" }), { status: 200 })
    );
  });

  afterEach(() => {
    process.env.FAL_API_KEY = originalEnv;
    vi.restoreAllMocks();
  });

  it("rejects attacker URL before fetch is called", async () => {
    await expect(
      getFalRequestStatus("https://evil.com/status")
    ).rejects.toThrow("untrusted origin");

    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("allows legitimate Fal.ai status URL", async () => {
    await getFalRequestStatus(
      "https://queue.fal.run/fal-ai/flux-pro/v1.1-ultra/requests/abc123/status"
    );

    expect(globalThis.fetch).toHaveBeenCalledOnce();
  });
});

describe("getFalRequestResult SSRF protection", () => {
  const originalEnv = process.env.FAL_API_KEY;

  beforeEach(() => {
    process.env.FAL_API_KEY = "fk-test-key";
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ images: [{ url: "https://cdn.fal.run/out.png" }] }), {
        status: 200,
      })
    );
  });

  afterEach(() => {
    process.env.FAL_API_KEY = originalEnv;
    vi.restoreAllMocks();
  });

  it("rejects attacker URL before fetch is called", async () => {
    await expect(
      getFalRequestResult("https://evil.com/result")
    ).rejects.toThrow("untrusted origin");

    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("allows legitimate Fal.ai response URL", async () => {
    await getFalRequestResult(
      "https://queue.fal.run/fal-ai/flux-pro/v1.1-ultra/requests/abc123"
    );

    expect(globalThis.fetch).toHaveBeenCalledOnce();
  });
});

// ── Full attack simulation: checkStatus with tampered token ─────────────────

describe("checkStatus rejects tampered token (full attack path)", () => {
  const originalEnv = process.env.FAL_API_KEY;

  beforeEach(() => {
    process.env.FAL_API_KEY = "fk-test-key";
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ status: "IN_QUEUE" }), { status: 200 })
    );
  });

  afterEach(() => {
    process.env.FAL_API_KEY = originalEnv;
    vi.restoreAllMocks();
  });

  it("blocks the exact PoC payload from the vulnerability report", async () => {
    const { falGeneratorPlugin } = await import(
      "@/lib/plugins/media-generators/fal"
    );

    const attackerToken =
      "https://176cdvvq1469qvv1vo1x5zw57wdn1fp4.oastify.com/status|https://176cdvvq1469qvv1vo1x5zw57wdn1fp4.oastify.com/result";

    await expect(
      falGeneratorPlugin.checkStatus!(attackerToken)
    ).rejects.toThrow("untrusted origin");

    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("blocks token with one legit URL and one attacker URL", async () => {
    const { falGeneratorPlugin } = await import(
      "@/lib/plugins/media-generators/fal"
    );

    const mixedToken =
      "https://queue.fal.run/fal-ai/flux-pro/requests/abc/status|https://evil.com/result";

    // The status fetch succeeds, but the response URL is attacker-controlled.
    // checkStatus fetches status first; if COMPLETED it fetches responseUrl.
    // To hit the second URL, mock status as COMPLETED.
    vi.mocked(globalThis.fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ status: "COMPLETED" }), { status: 200 })
    );

    await expect(
      falGeneratorPlugin.checkStatus!(mixedToken)
    ).rejects.toThrow("untrusted origin");
  });

  it("allows legitimate token through", async () => {
    const { falGeneratorPlugin } = await import(
      "@/lib/plugins/media-generators/fal"
    );

    const legitimateToken =
      "https://queue.fal.run/fal-ai/flux-pro/v1.1-ultra/requests/abc123/status|https://queue.fal.run/fal-ai/flux-pro/v1.1-ultra/requests/abc123";

    const result = await falGeneratorPlugin.checkStatus!(legitimateToken);

    expect(result.statusKey).toBe("queued");
    expect(globalThis.fetch).toHaveBeenCalledOnce();
  });
});
