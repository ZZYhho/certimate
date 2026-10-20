// Informational side effects must never turn a successful configuration save into a failure.
export function notifyNodeConfigSaved<T>(callback: ((values: T) => void | Promise<void>) | undefined, values: T): void {
  try {
    Promise.resolve(callback?.(values)).catch(() => {});
  } catch {
    // A synchronous callback failure is isolated too.
  }
}
