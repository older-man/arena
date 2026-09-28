// Site integration is intentionally isolated: inspect Arena DOM when these drift.
export const defaults = {
  replies:'[data-message-author-role="assistant"], [data-role="assistant"]',
  composer:'textarea[placeholder], [contenteditable="true"][role="textbox"]',
  send:'button[type="submit"], button[aria-label*="Send" i], button[aria-label*="发送"]'
};
export function selector(value: unknown, fallback: string) {
  return typeof value==='string' && value.trim() ? value.trim() : fallback;
}
