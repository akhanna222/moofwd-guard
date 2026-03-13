/**
 * MoofwdGuard Browser Signal Collector
 *
 * Usage:
 *   import { initMoofwdTracker } from './moofwd-tracker.js'
 *   const deviceFingerprint = await initMoofwdTracker(
 *       'https://api.moofwdguard.com',
 *       '#card-number-field'
 *   )
 *   // pass deviceFingerprint into your /v1/decisions request
 */

export async function initMoofwdTracker(apiBase, cardFieldSelector) {
  try {
    // 1. Load FingerprintJS
    const FingerprintJS = await import(
      "https://openfpcdn.io/fingerprintjs/v4"
    );
    const fp = await FingerprintJS.default.load();
    const fpResult = await fp.get();
    const visitorId = fpResult.visitorId;

    // 2. Device signals
    const userAgent = navigator.userAgent;
    const browserLanguage = navigator.language;
    const screenResolution = `${screen.width}x${screen.height}`;
    const timezoneOffset = new Date().getTimezoneOffset();

    let webglHash = null;
    try {
      const gl = document.createElement("canvas").getContext("webgl");
      if (gl) {
        const ext = gl.getExtension("WEBGL_debug_renderer_info");
        if (ext) {
          webglHash = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL);
        }
      }
    } catch (_) {
      // WebGL not available
    }

    const isHeadless = !!navigator.webdriver;

    // 3. Behavioural signals
    let mouseMovementPresent = false;
    let copyPasteDetected = false;
    let pageFocusLostCount = 0;
    let scrollEventCount = 0;
    const pageLoadTime = Date.now();

    document.addEventListener(
      "mousemove",
      () => {
        mouseMovementPresent = true;
      },
      { once: true }
    );

    document.addEventListener("scroll", () => {
      scrollEventCount++;
    });

    const cardField = document.querySelector(cardFieldSelector);
    if (cardField) {
      cardField.addEventListener("paste", () => {
        copyPasteDetected = true;
      });
    }

    document.addEventListener("visibilitychange", () => {
      if (document.hidden) {
        pageFocusLostCount++;
      }
    });

    // 4. Intercept form submit
    const form = cardField ? cardField.closest("form") : null;
    if (form) {
      form.addEventListener("submit", async (event) => {
        event.preventDefault();

        const checkoutDuration = (Date.now() - pageLoadTime) / 1000;
        const transactionId =
          form.dataset.transactionId || crypto.randomUUID();

        const payload = {
          transaction_id: transactionId,
          ip_address: "0.0.0.0", // Server will determine real IP
          email: form.querySelector('[name="email"]')?.value || "",
          bin: (
            form.querySelector('[name="card_number"]')?.value || ""
          ).replace(/\s/g, "").slice(0, 6),
          billing_country:
            form.querySelector('[name="billing_country"]')?.value || "US",
          device_fingerprint: visitorId,
          checkout_duration_seconds: checkoutDuration,
          user_agent: userAgent,
          browser_language: browserLanguage,
          screen_resolution: screenResolution,
          timezone_offset: timezoneOffset,
          webgl_hash: webglHash,
          mouse_movement_present: mouseMovementPresent,
          copy_paste_detected: copyPasteDetected,
          page_focus_lost_count: pageFocusLostCount,
          scroll_event_count: scrollEventCount,
        };

        try {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 2000);

          await fetch(`${apiBase}/v1/signals`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
            signal: controller.signal,
          });

          clearTimeout(timeout);
        } catch (err) {
          console.warn("[MoofwdGuard] Signal POST failed, proceeding:", err);
        }

        // Re-fire the original submit
        form.requestSubmit();
      });
    }

    return visitorId;
  } catch (err) {
    console.warn("[MoofwdGuard] Tracker init failed:", err);
    return null;
  }
}
