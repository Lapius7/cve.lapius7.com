/** Stacked ghost cards shown when a list has no records. Uses theme tokens so it follows light and dark. */
export default function EmptyArt() {
  return (
    <svg width="168" height="76" viewBox="0 0 224 100" fill="none" aria-hidden="true" style={{ color: 'var(--text-secondary, currentColor)' }}>
      <rect x="22" y="4" width="180" height="40" rx="14" fill="currentColor" opacity=".35" />
      <rect x="12" y="14" width="200" height="40" rx="14" fill="currentColor" opacity=".5" />
      <rect x="1" y="26" width="222" height="72" rx="16" fill="var(--background, #0b0b0b)" stroke="currentColor" strokeOpacity=".3" />
      <rect x="22" y="44" width="32" height="32" rx="6" fill="currentColor" opacity=".7" />
      <rect x="66" y="45" width="120" height="10" rx="5" fill="currentColor" opacity=".7" />
      <rect x="66" y="63" width="64" height="8" rx="4" fill="currentColor" opacity=".5" />
    </svg>
  )
}
