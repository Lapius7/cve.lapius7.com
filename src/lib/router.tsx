import { useEffect, useState, type AnchorHTMLAttributes, type MouseEvent } from 'react'

export type L = 'en' | 'ja'
export const langOf = (p = location.pathname): L | null => p.match(/^\/(ja|en)(?=\/|$)/)?.[1] as L | null
export const isJaPath = (p = location.pathname) => langOf(p) === 'ja'
export const stripLang = (p: string) => p.replace(/^\/(ja|en)(?=\/|$)/, '') || '/'
export const withLang = (href: string, lang: L = langOf() ?? 'en') =>
  href.startsWith('/') ? `/${lang}${href === '/' ? '' : href}` : href
export const prefLang = (): L => (localStorage.getItem('lang') as L) ?? (navigator.language.startsWith('ja') ? 'ja' : 'en')

export function navigate(to: string, top = true) {
  history.pushState(null, '', to)
  window.dispatchEvent(new PopStateEvent('popstate'))
  if (top) scrollTo({ top: 0 })
}

export function usePath() {
  const [path, setPath] = useState(location.pathname)
  useEffect(() => {
    const on = () => setPath(location.pathname)
    window.addEventListener('popstate', on)
    return () => window.removeEventListener('popstate', on)
  }, [])
  return path
}

export function Link({ href: raw, onClick, ...p }: AnchorHTMLAttributes<HTMLAnchorElement> & { href: string }) {
  const href = withLang(raw)
  return (
    <a
      href={href}
      onClick={(e: MouseEvent<HTMLAnchorElement>) => {
        onClick?.(e)
        if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return
        e.preventDefault()
        navigate(href)
      }}
      {...p}
    />
  )
}
