import Markdown from 'react-markdown';
// Explicit protocol allowlist; never allow raw HTML or network image embedding.
function safeUrl(url: string) {
  if (/[\u0000-\u0020\u007f]/.test(url)) return '';
  if (/^(?:https?:|mailto:)/i.test(url)) return url;
  if (/^[a-z][a-z\d+.-]*:/i.test(url) || url.startsWith('//') || url.includes('\\')) return '';
  return url;
}
export function SafeMarkdown({ content }: { content: string }) {
  return <div className="markdown"><Markdown skipHtml urlTransform={safeUrl} components={{
    img: ({alt}) => <span className="muted">[Image: {alt || 'omitted'} — embedding disabled]</span>,
    a: ({href,children}) => href ? <a href={href} rel="noopener noreferrer">{children}</a> : <span>{children}</span>,
  }}>{content}</Markdown></div>;
}
