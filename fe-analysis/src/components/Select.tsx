import { useEffect, useId, useRef, useState, type KeyboardEvent, type ReactNode } from 'react'

export interface SelectOption<T extends string | number> {
  value: T
  label: string
  // icon renders before the label, both in the trigger and in the list.
  icon?: ReactNode
}

interface SelectProps<T extends string | number> {
  value: T
  options: SelectOption<T>[]
  onChange: (value: T) => void
  // placement 'top' opens the list upward, for triggers near the bottom of the page.
  placement?: 'bottom' | 'top'
  size?: 'sm' | 'md'
  className?: string
  'aria-label'?: string
  'aria-labelledby'?: string
}

// Select is a listbox dropdown: a trigger button plus a popup list, driven by
// mouse or keyboard (arrows, Home/End, Enter/Space, Escape, type-ahead).
export default function Select<T extends string | number>({
  value,
  options,
  onChange,
  placement = 'bottom',
  size = 'md',
  className = '',
  ...aria
}: SelectProps<T>) {
  const [open, setOpen] = useState(false)
  const [activeIndex, setActiveIndex] = useState(0)
  const rootRef = useRef<HTMLDivElement>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const listRef = useRef<HTMLUListElement>(null)
  const listId = useId()

  const selectedIndex = Math.max(
    0,
    options.findIndex((option) => option.value === value),
  )
  const selected = options[selectedIndex]

  useEffect(() => {
    if (!open) return
    const onPointerDown = (event: PointerEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false)
    }
    document.addEventListener('pointerdown', onPointerDown)
    return () => document.removeEventListener('pointerdown', onPointerDown)
  }, [open])

  useEffect(() => {
    if (!open) return
    listRef.current?.focus()
  }, [open])

  useEffect(() => {
    if (!open) return
    const item = listRef.current?.children[activeIndex] as HTMLElement | undefined
    item?.scrollIntoView({ block: 'nearest' })
  }, [open, activeIndex])

  const openList = () => {
    setActiveIndex(selectedIndex)
    setOpen(true)
  }

  const close = () => {
    setOpen(false)
    triggerRef.current?.focus()
  }

  const choose = (index: number) => {
    const option = options[index]
    if (option && option.value !== value) onChange(option.value)
    close()
  }

  const onTriggerKeyDown = (event: KeyboardEvent<HTMLButtonElement>) => {
    if (['ArrowDown', 'ArrowUp', 'Enter', ' '].includes(event.key)) {
      event.preventDefault()
      openList()
    }
  }

  const onListKeyDown = (event: KeyboardEvent<HTMLUListElement>) => {
    const last = options.length - 1
    switch (event.key) {
      case 'ArrowDown':
        event.preventDefault()
        setActiveIndex((i) => Math.min(last, i + 1))
        break
      case 'ArrowUp':
        event.preventDefault()
        setActiveIndex((i) => Math.max(0, i - 1))
        break
      case 'Home':
        event.preventDefault()
        setActiveIndex(0)
        break
      case 'End':
        event.preventDefault()
        setActiveIndex(last)
        break
      case 'Enter':
      case ' ':
        event.preventDefault()
        choose(activeIndex)
        break
      case 'Escape':
        event.preventDefault()
        close()
        break
      case 'Tab':
        setOpen(false)
        break
      default:
        if (event.key.length === 1) {
          const key = event.key.toLowerCase()
          const match = options.findIndex((option) => option.label.toLowerCase().startsWith(key))
          if (match >= 0) setActiveIndex(match)
        }
    }
  }

  const sizing = size === 'sm' ? 'px-2 py-1 text-sm' : 'px-3 py-2 text-sm'

  return (
    <div ref={rootRef} className={`relative ${className}`}>
      <button
        ref={triggerRef}
        type="button"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={open ? listId : undefined}
        onClick={() => (open ? setOpen(false) : openList())}
        onKeyDown={onTriggerKeyDown}
        {...aria}
        className={`flex w-full items-center justify-between gap-2 rounded-md border bg-white text-left focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 ${open ? 'border-indigo-500 ring-1 ring-indigo-500' : 'border-slate-300 hover:border-slate-400'} ${sizing}`}
      >
        <span className="flex min-w-0 items-center gap-2 truncate text-slate-800">
          {selected?.icon}
          {selected?.label}
        </span>
        <svg
          aria-hidden="true"
          viewBox="0 0 20 20"
          className={`h-4 w-4 shrink-0 text-slate-400 ${open ? 'rotate-180' : ''}`}
        >
          <path fill="currentColor" d="M5.3 7.3a1 1 0 0 1 1.4 0L10 10.6l3.3-3.3a1 1 0 1 1 1.4 1.4l-4 4a1 1 0 0 1-1.4 0l-4-4a1 1 0 0 1 0-1.4Z" />
        </svg>
      </button>

      {open ? (
        <ul
          ref={listRef}
          id={listId}
          role="listbox"
          tabIndex={-1}
          aria-activedescendant={`${listId}-${activeIndex}`}
          onKeyDown={onListKeyDown}
          className={`absolute z-20 max-h-60 min-w-full overflow-auto rounded-md border border-slate-200 bg-white py-1 text-sm shadow-lg focus:outline-none ${placement === 'top' ? 'bottom-full mb-1' : 'top-full mt-1'}`}
        >
          {options.map((option, index) => {
            const isSelected = index === selectedIndex
            const isActive = index === activeIndex
            return (
              <li
                key={String(option.value)}
                id={`${listId}-${index}`}
                role="option"
                aria-selected={isSelected}
                onPointerEnter={() => setActiveIndex(index)}
                onClick={() => choose(index)}
                className={`flex cursor-pointer items-center justify-between gap-3 whitespace-nowrap px-3 py-1.5 ${isActive ? 'bg-indigo-50 text-indigo-700' : 'text-slate-700'} ${isSelected ? 'font-semibold' : ''}`}
              >
                <span className="flex items-center gap-2">
                  {option.icon}
                  {option.label}
                </span>
                {isSelected ? (
                  <svg aria-hidden="true" viewBox="0 0 20 20" className="h-4 w-4 text-indigo-600">
                    <path fill="currentColor" d="M16.7 5.3a1 1 0 0 1 0 1.4l-8 8a1 1 0 0 1-1.4 0l-4-4a1 1 0 1 1 1.4-1.4L8 12.6l7.3-7.3a1 1 0 0 1 1.4 0Z" />
                  </svg>
                ) : null}
              </li>
            )
          })}
        </ul>
      ) : null}
    </div>
  )
}
