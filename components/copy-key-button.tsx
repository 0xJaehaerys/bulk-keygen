'use client';
import { useEffect, useRef, useState } from 'react';
import { Check, Copy } from 'lucide-react';

export function CopyKeyButton({ value, label }: { value: string; label: string }) {
  const [feedback, setFeedback] = useState('');
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);
  async function copy() {
    clearTimeout(timer.current);
    try { await navigator.clipboard.writeText(value); setFeedback('Copied'); }
    catch { setFeedback('Copy unavailable. Select the value manually.'); }
    timer.current = setTimeout(() => setFeedback(''), 4000);
  }
  return <span className="copy-control">
    <button className="btn icon" type="button" aria-label={label} onClick={() => void copy()}>{feedback === 'Copied' ? <Check size={16}/> : <Copy size={16}/>}</button>
    <output className="copy-feedback">{feedback}</output>
  </span>;
}
