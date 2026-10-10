/** A failure that retrying cannot fix (failed healthcheck → already rolled back, tampered plan, …): the execution fails now. */
export class TerminalStepError extends Error {}
