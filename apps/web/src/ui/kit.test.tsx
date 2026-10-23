import { act, render, screen, fireEvent } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { HoldToSign, Sev } from './kit';

describe('HoldToSign', () => {
  beforeEach(() => { vi.useFakeTimers({ toFake: ['requestAnimationFrame', 'cancelAnimationFrame', 'performance'] }); });
  afterEach(() => vi.useRealTimers());
  const run = (ms: number) => act(() => { vi.advanceTimersByTime(ms); });

  it('does nothing on a quick click and confirms exactly once after a full hold', () => {
    const ok = vi.fn(); render(<HoldToSign label="Firmar" ms={1000} onConfirm={ok} />);
    const b = screen.getByRole('button', { name: /Firmar/ });
    fireEvent.pointerDown(b); run(300); fireEvent.pointerUp(b); run(2000);
    expect(ok).not.toHaveBeenCalled();
    fireEvent.pointerDown(b); run(1100); expect(ok).toHaveBeenCalledTimes(1);
    run(2000); expect(ok).toHaveBeenCalledTimes(1);
  });
  it('works from the keyboard and cancels on blur', () => {
    const ok = vi.fn(); render(<HoldToSign label="Firmar" ms={500} onConfirm={ok} />);
    const b = screen.getByRole('button', { name: /Firmar/ });
    fireEvent.keyDown(b, { key: ' ' }); run(200); fireEvent.blur(b); run(1000); expect(ok).not.toHaveBeenCalled();
    fireEvent.keyDown(b, { key: 'Enter' }); run(600); expect(ok).toHaveBeenCalledTimes(1);
  });
  it('is inert when disabled', () => {
    const ok = vi.fn(); render(<HoldToSign label="Firmar" ms={100} disabled onConfirm={ok} />);
    fireEvent.pointerDown(screen.getByRole('button')); run(500); expect(ok).not.toHaveBeenCalled();
  });
});
describe('Sev', () => { it('names the level in text, not only colour', () => { render(<Sev level="critical" />); expect(screen.getByText('Crítica')).toBeTruthy(); }); });
